using System.ComponentModel.DataAnnotations;
using Auth.Models;

namespace Auth.DTOs
{
    public class UpdateRequest
    {
        private string _email;
        private string _password;
        private string _confrimPassword;
        private string _role;


        [EnumDataType(typeof(Role))]
        public string Role
        {
            get => _role;
            set => _role = replaceEmptyWithNull(value);
        }

        [EmailAddress]
        public string Email { get => _email; set => _email = replaceEmptyWithNull(value); }

        [MinLength(6)]
        public string Password { get => _password; set => _password = replaceEmptyWithNull(value); }

        [Compare("Password")]
        public string ConfrimPassword { get => _confrimPassword; set => _confrimPassword = replaceEmptyWithNull(value); }

        public string Title { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }

        private string replaceEmptyWithNull(string value)
        {
            return string.IsNullOrEmpty(value) ? null : value;
        }

    }
}

/*
Some validation attributes don't handle empty strings well,
so the properties with validation attributes replace empty strings
with null on set to ensure that empty string values are ignored.
*/