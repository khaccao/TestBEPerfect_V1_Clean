using Microsoft.AspNetCore.Mvc;

namespace PerfectKeyV1.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class HealthController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return Ok(new
        {
            Status = "Healthy",
            Timestamp = DateTime.UtcNow,
            Service = "PerfectKey API",
            Version = "1.0.0"
        });
    }
}