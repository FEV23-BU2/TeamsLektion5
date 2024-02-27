using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace TeamsLektion5;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddDbContext<ApplicationContext>(options =>
        {
            options.UseNpgsql(
                "Host=localhost;Database=teamslektion5;Username=postgres;Password=password"
            );
        });

        // Process för autentisering
        // 1. Registrera användare (namn + lösenord)
        // 2. Logga in (med namn + lösenord) och få token
        // 3. Vid varje request: använd token värdet

        builder.Services.AddAuthentication().AddBearerToken(IdentityConstants.BearerScheme);

        builder.Services.AddAuthorization(options =>
        {
            options.AddPolicy(
                "get_all_todos",
                policy =>
                {
                    policy.RequireAuthenticatedUser().RequireRole("admin");
                }
            );
        });

        builder.Services.AddControllers();
        builder.Services.AddTransient<IClaimsTransformation, MyClaimsTransformation>();

        SetupSecurity(builder);

        // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        var app = builder.Build();

        app.MapIdentityApi<User>();
        app.UseAuthentication();
        app.UseAuthorization();

        // Configure the HTTP request pipeline.
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.MapControllers();
        app.UseHttpsRedirection();

        app.Run();
    }

    public static void SetupSecurity(WebApplicationBuilder builder)
    {
        builder
            .Services.AddIdentityCore<User>()
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<ApplicationContext>()
            .AddApiEndpoints();
    }
}

public class MyClaimsTransformation : IClaimsTransformation
{
    UserManager<User> userManager;

    public MyClaimsTransformation(UserManager<User> userManager)
    {
        this.userManager = userManager;
    }

    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        ClaimsIdentity claims = new ClaimsIdentity();

        var id = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (id != null)
        {
            var user = await userManager.FindByIdAsync(id);
            if (user != null)
            {
                var userRoles = await userManager.GetRolesAsync(user);
                foreach (var userRole in userRoles)
                {
                    claims.AddClaim(new Claim(ClaimTypes.Role, userRole));
                }
            }
        }

        principal.AddIdentity(claims);
        return await Task.FromResult(principal);
    }
}

public class User : IdentityUser
{
    public List<Todo> Todos { get; set; } = new List<Todo>();
}

public class Todo
{
    public int Id { get; set; }
    public string Title { get; set; } = "";
    public User User { get; set; } = null;
}

public class TodoDto
{
    public int Id { get; set; }
    public string Title { get; set; }

    public TodoDto(Todo todo)
    {
        this.Id = todo.Id;
        this.Title = todo.Title;
    }
}

// Vi behöver ingen 'DbSet' för 'User', för det lägger ASP.NET in automatiskt.
public class ApplicationContext : IdentityDbContext<User>
{
    public DbSet<Todo> Todos { get; set; }

    public ApplicationContext(DbContextOptions<ApplicationContext> options)
        : base(options) { }
}

[ApiController]
[Route("todo")]
public class TodoController : ControllerBase
{
    ApplicationContext context;
    UserManager<User> userManager;
    RoleManager<IdentityRole> roleManager;

    public TodoController(
        ApplicationContext context,
        UserManager<User> userManager,
        RoleManager<IdentityRole> roleManager
    )
    {
        this.context = context;
        this.userManager = userManager;
        this.roleManager = roleManager;
    }

    [HttpPost("role")]
    public async Task<string> CreateRole([FromQuery] string name)
    {
        await roleManager.CreateAsync(new IdentityRole(name));
        return "Created role " + name;
    }

    [HttpPost("user-role")]
    [Authorize]
    public async Task<string> AddRoleToUser([FromQuery] string role)
    {
        User? user = context.Users.Find(User.FindFirstValue(ClaimTypes.NameIdentifier));
        await userManager.AddToRoleAsync(user, role);
        return "Added role " + role + " to user " + user.UserName;
    }

    [HttpPost]
    [Authorize]
    public IActionResult CreateTodo([FromQuery] string title)
    {
        User? user = context.Users.Find(User.FindFirstValue(ClaimTypes.NameIdentifier));

        Todo todo = new Todo();
        todo.Title = title;
        todo.User = user;

        user.Todos.Add(todo);

        context.Todos.Add(todo);
        context.SaveChanges();

        return Ok(new TodoDto(todo));
    }

    [HttpGet]
    [Authorize("get_all_todos")]
    public List<TodoDto> GetAllTodos()
    {
        return context.Todos.ToList().Select(todo => new TodoDto(todo)).ToList();
    }
}
