using PerfectKeyV1.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace PerfectKeyV1.Application.Interfaces
{
    public interface IJwtService
    {
        string GenerateJwtToken(User user);
        string GenerateRefreshToken();
        string? ValidateJwtToken(string token);
        string GetUserIdFromToken(string token);
        ClaimsPrincipal GetPrincipalFromToken(string token);
    }
}
