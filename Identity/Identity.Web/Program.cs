using Identity.Web.Claims;
using Identity.Web.Context;
using Identity.Web.Entities;
using Identity.Web.SendGrid;
using Identity.Web.Services;
using Identity.Web.Services.EmailSettings;
using Identity.Web.Services.TwoFactor;
using Identity.Web.Validators;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<ProjectContext>(opt => opt.UseSqlServer(builder.Configuration.GetConnectionString("DefualtConnection")));

builder.Services.AddAuthorization(conf =>
{
    conf.AddPolicy("�stanbulPolicy", policy =>
    {
        policy.RequireClaim("City", "�stanbul");
    });

    conf.AddPolicy("BirthDayPolicy", policy =>
    {
        policy.RequireClaim("BirthDay");

    });

    conf.AddPolicy("ExpireDatePolicy", policy =>
    {
        policy.AddRequirements(new PaymentClaim());

    });

});

#region Facebook,Google,Microsoft giri� i�lemleri ayarlar�

builder.Services.AddAuthentication().AddFacebook(conf =>
{
    conf.AppId = builder.Configuration["Authentication:Facebook:AppId"];
    conf.AppSecret = builder.Configuration["Authentication:Facebook:AppSecret"];
}).AddGoogle(conf =>
{
    conf.ClientId = builder.Configuration["Authentication:Google:ClientID"];
    conf.ClientSecret = builder.Configuration["Authentication:Google:Clientsecret"];
}).AddMicrosoftAccount(conf =>
{
    conf.ClientId = builder.Configuration["Authentication:Microsoft:ClientID"];
    conf.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"];

});

#endregion


builder.Services.AddIdentity<AppUser, AppRole>(opt =>
{
    opt.Password.RequireNonAlphanumeric = false;
    opt.Password.RequiredLength = 1;
    opt.Password.RequireLowercase = false;
    opt.Password.RequireUppercase = false;


    opt.User.RequireUniqueEmail = true;
    //opt.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

    opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    opt.Lockout.MaxFailedAccessAttempts = 3;

}).AddPasswordValidator<PasswordValidator>().AddUserValidator<UserValidator>().AddErrorDescriber<ErrorDescriptor>().AddEntityFrameworkStores<ProjectContext>().AddDefaultTokenProviders();

builder.Services.Configure<DataProtectionTokenProviderOptions>(opt => opt.TokenLifespan = TimeSpan.FromHours(1));//Token�n �mr�n� 2 saat yapt�k �ifremi unuttum i�in

builder.Services.Configure<SecurityStampValidatorOptions>(opt => { opt.ValidationInterval = TimeSpan.FromHours(1); }); // Security stamp de�erini her saat ba�� kontrol eder..

builder.Services.AddSingleton<IFileProvider>(new PhysicalFileProvider(Directory.GetCurrentDirectory()));

builder.Services.Configure<EmailSettingModel>(builder.Configuration.GetSection("EmailSettings"));
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<EmailConfirmService>();

builder.Services.Configure<TwoFactorOptions>(builder.Configuration.GetSection("SendGrid"));

builder.Services.AddScoped<TwoFactorService>();

builder.Services.AddScoped<CodeVerification>();

builder.Services.AddScoped<EmailSender>();

builder.Services.AddTransient<IAuthorizationHandler, PaymentClaimHandler>();

CookieBuilder cookieBuilder = new();
cookieBuilder.Name = "Identity"; // Cookie ismi
cookieBuilder.HttpOnly = true; // Client taraf�nda cookie bilgisi okunamaz
/*cookieBuilder.Expiration = TimeSpan.FromSeconds(30);*/ // Cookie bilgisini 30 saniye tutar
cookieBuilder.SameSite = SameSiteMode.Strict; // Cookie bilgisi sadece o site �zerinden eri�ilebilir olur.
cookieBuilder.SecurePolicy = CookieSecurePolicy.SameAsRequest;// Http veya https hangisindne yollan�rsa cookie bilgisini oradan g�nderir.
//Always: Https istek �zerinden gelirse kullan�c�n�n cookie bilgisini g�nderir

builder.Services.ConfigureApplicationCookie(conf =>
{
    conf.LoginPath = new PathString("/User/Login");
    conf.Cookie = cookieBuilder;
    conf.ExpireTimeSpan = System.TimeSpan.FromMinutes(5);
    conf.SlidingExpiration = false; // Kullan�c� cookie bilgisinin yar�s�n� ge�ti�in de siteye istek atar ve cookie bilgisini bizim verdi�imiz s�re kadar zaman ekler.
    conf.LogoutPath = new PathString("/User/Logout2");
    conf.AccessDeniedPath = new PathString("/User/AccessDenied"); // Kullan�c�n�n o sayfaya yetkisi olmad��� bilgisini burada g�sterebiliriz.
});

builder.Services.AddScoped<IClaimsTransformation, ClaimTransformation>();

builder.Services.AddSession(opt => { opt.IdleTimeout = TimeSpan.FromSeconds(120); opt.Cookie.Name = "Session"; }); // session bilgisini burada tutaca��z

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseSession();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
