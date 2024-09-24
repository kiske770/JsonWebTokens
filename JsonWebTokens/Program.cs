using JsonWebTokens.Utils;
using System;
using System.Security.Claims;

namespace JsonWebTokens
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Digite el nombre de usuario...");
            var userName = Console.ReadLine();

            Console.WriteLine("Digite la contraseña de usuario...");
            var userId = Console.ReadLine();

            if (ValidateCredentials(userName, userId))
            {
                var token = JwtFunctions.GenerateJwtToken(userId, userName);
                Console.WriteLine($"\n\nToken generado: {token}\n\n");
                VerifyToken(token);
            }
            else
            {
                Console.WriteLine("\nUsuario o contraseña invalidos.");

            }

            Console.Read();
        }

        private static bool ValidateCredentials(string userName, string userId)
        {
            if (string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(userId))
                return false;

            return true;
        }

        private static void VerifyToken(string token)
        {
            Console.WriteLine("\n\nValidando token...\n\n");
            System.Threading.Thread.Sleep(3000
                );
            
            var principal = JwtFunctions.ValidateJwtToken(token);
            if (principal != null)
            {
                Console.WriteLine("Token Válido");
                Console.WriteLine($"Username: {principal.FindFirst(ClaimTypes.Name)?.Value}");
                Console.WriteLine($"Password: {principal.FindFirst(ClaimTypes.NameIdentifier)?.Value}");
            }
            else
            {
                Console.WriteLine("Token inválido");
            }
        }
    }
}
