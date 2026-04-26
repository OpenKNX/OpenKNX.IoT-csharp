using OpenKNX.IoT;
using OpenKNX.IoT.Demo.Classes;
using OpenKNX.IoT.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddLogging(builder =>
{
    builder.AddConsole();
});

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddSingleton<KnxIotDevice>(provider =>
{
    var loggerFactory = provider.GetRequiredService<ILoggerFactory>();
    return new KnxIotDevice(loggerFactory);
});

builder.Services.AddSingleton<WebsocketHandler>();

builder.Services.AddSingleton<LogicHandler>(provider =>
{
    var device = provider.GetRequiredService<KnxIotDevice>();
    var websocket = provider.GetRequiredService<WebsocketHandler>();
    var logic = new LogicHandler(websocket, device);
    websocket.SetLogicHandler(logic);
    var loggerFactory = provider.GetRequiredService<ILoggerFactory>();
    websocket.SetLogger(loggerFactory);
    return logic;
});

var app = builder.Build();
// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}
app.UseRouting();

app.UseAuthorization();

app.MapStaticAssets();

app.UseWebSockets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

InitialDeviceConfig? config = null;
if(Environment.GetEnvironmentVariable("Serialnumber") != null)
{
    app.Logger.LogInformation("Loading configuration from environment variables");
    config = new InitialDeviceConfig
    {
        Serialnumber = Environment.GetEnvironmentVariable("Serialnumber")!,
        Password = Environment.GetEnvironmentVariable("Password") ?? "Unknown",
        Model = Environment.GetEnvironmentVariable("Model") ?? "Unknown",
        HardwareType = Environment.GetEnvironmentVariable("HardwareType") ?? "Unknown",
        HardwareVersion = Environment.GetEnvironmentVariable("HardwareVersion") ?? "Unknown",
        FirmwareVersion = Environment.GetEnvironmentVariable("FirmwareVersion") ?? "Unknown",

        KeyId = Environment.GetEnvironmentVariable("KeyId") ?? "Unknown",
        KeyIdContext = Environment.GetEnvironmentVariable("KeyIdContext") ?? "Unknown",
        MasterSecret = Environment.GetEnvironmentVariable("MasterSecret") ?? "Unknown",
    };
} else
{
    List<string> configPaths = new()
    {
        "/config/device.json",
        "device.json"
    };
    string configPath = string.Empty;

    foreach (string path in configPaths)
    {
        if (File.Exists(path))
        {
            configPath = path;
            break;
        }
    }
    if (string.IsNullOrEmpty(configPath))
    {
        app.Logger.LogError("No configuration file found. Please ensure that 'device.json' is present in the application directory or in the '/config' folder.");
        Environment.Exit(1);
    }
    app.Logger.LogInformation("Loading configuration from {ConfigPath}", configPath);

    config = System.Text.Json.JsonSerializer.Deserialize<InitialDeviceConfig>(File.ReadAllText(configPath));
}

if (config == null)
{
    app.Logger.LogError("Failed load configuration");
    Environment.Exit(1);
}

app.Logger.LogInformation("Configuration loaded:\nSerialnumber:\t{Serialnumber}\nModel:\t{Model}\nHardwareType:\t{HardwareType}\nHardwareVersion:\t{HardwareVersion}\nFirmwareVersion:\t{FirmwareVersion}",
    config.Serialnumber, config.Model, config.HardwareType, config.HardwareVersion, config.FirmwareVersion);

var device = app.Services.GetRequiredService<KnxIotDevice>();
device.Start(config);
var logicHandler = app.Services.GetRequiredService<LogicHandler>();

app.Run();