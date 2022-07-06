namespace Auth.Repository.Interfaces
{
    public interface IEmailRepository
    {
        void Send(string to, string subject, string html, string from = null);
    }
}

// sridharpadmanaben@gmail.com