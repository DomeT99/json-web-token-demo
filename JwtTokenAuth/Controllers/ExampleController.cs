using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JwtTokenAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "Admin")]
    public class ExampleController : ControllerBase
    {
        public List<string> animals = new()
        {
            "Bear",
            "Pig",
            "Dog"
        };

        [HttpGet]
        public IEnumerable<string> GetAnimals()
        {
            return animals;
        }
    }
}
