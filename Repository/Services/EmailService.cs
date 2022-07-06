using Microsoft.Extensions.Options;

using MimeKit;
using MailKit.Net.Smtp;

using Auth.Helper;
using Auth.Repository.Interfaces;

namespace Auth.Repository.Services
{
    public class EmailService : IEmailRepository
    {
        private readonly AppSettings _appSetting;
        public EmailService(IOptions<AppSettings> appSetting)
        {
            _appSetting = appSetting.Value;
        }

        public void Send(string to, string subject, string html, string from = null)
        {
            using (var email = new MimeMessage())
            {
                // 01) Creating message

                email.From.Add(MailboxAddress.Parse(from ?? _appSetting.EmailFrom));
                email.To.Add(MailboxAddress.Parse(to));
                email.Subject = subject;
                email.Body = new TextPart(MimeKit.Text.TextFormat.Html) { Text = html };

                // 02) sending mail

                using var smtp = new SmtpClient();
                smtp.Connect(_appSetting.SmtpHost, _appSetting.SmtpPort, MailKit.Security.SecureSocketOptions.StartTls);
                smtp.Authenticate(_appSetting.SmtpUser, _appSetting.SmtpPass);
                smtp.Send(email);
                smtp.Disconnect(true);
            }
        }
    }
}