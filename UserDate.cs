using Newtonsoft.Json;
namespace InstaWebAPI.UserDate
{
    public class UserDate
    {
        [JsonProperty("username")]
        public string Username { get; set; }
        [JsonProperty("enc_password")]
        public string Password { get; set; }
    }
}