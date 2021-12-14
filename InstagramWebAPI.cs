using InstaWebAPI.Response;
using InstaWebAPI.DateTimeHelper;
using InstaWebAPI.Webhelper;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace InstaWebAPI
{
    public class InstaWebAPI
    {

        //Declaração das Variareis
        private CookieContainer Cookies { get; set; }
        private Dictionary<string, string> ListCookie { get; set; }
        private Uri BasicUrl { get; set; }
        private string CSRFTOKEN { get; set; }
        private HttpClientHandler Handler { get; set; }
        private HttpClient Client { get; set; }
        private long UserID { get; set; }
        private string UserAgent { get; set; }
        public UserDate.UserDate User { get; set; }
        private dynamic _shareddata { get; set; }
        private string X_IG_WWW_CLAIM { get; set; }
        private string Challenge_URL { get; set; }

        /// <summary>
        /// Initial configuration of InstagramWebAPI
        /// </summary>
        /// <param name="User">UserDate with Username and Password of account</param>
        /// <param name="PrivateUserAgent">If you want to use Private UserAgent</param>
        /// <param name="PrivateUserAgentString">Private userAgent string</param>
        /// <returns>Create instace osf InstagramWebAPI</returns>
        public InstaWebAPI(UserDate.UserDate User, bool PrivateUserAgent = false, string PrivateUserAgentString = "")
        {
            this.Challenge_URL = "challenge/";
            this.User = User;
            this.BasicUrl = new Uri("https://www.instagram.com");
            this.Cookies = new CookieContainer();
            this.Cookies.Add(this.BasicUrl, new Cookie("ig_cb", "1"));
            this.X_IG_WWW_CLAIM = "";
            this.Handler = new HttpClientHandler
            {
                CookieContainer = this.Cookies,
                UseCookies = true,
                UseDefaultCredentials = false
            };
            this.Client = new HttpClient(this.Handler)
            {
                BaseAddress = this.BasicUrl,
                Timeout = TimeSpan.FromSeconds(35)
            };
            this.Client.DefaultRequestHeaders.Add("Accept-Language", "en-US");
            this.Client.DefaultRequestHeaders.Add("X-Instagram-AJAX", "1");
            if (PrivateUserAgent)
                this.UserAgent = PrivateUserAgentString;
            else
                this.UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:21.0) Gecko/20100101 Firefox/21.0";
            if (String.IsNullOrEmpty(this.UserAgent))
                this.UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:21.0) Gecko/20100101 Firefox/21.0";
            this.Client.DefaultRequestHeaders.Add("User-Agent", this.UserAgent);
            this.Client.DefaultRequestHeaders.Add("X-Requested-With", "XMLHttpRequest");
            this.Client.DefaultRequestHeaders.Add("Referer", this.BasicUrl.ToString());
            HttpResponseMessage response = this.Client.GetAsync(this.BasicUrl).Result;
            var aux = this.Handler.CookieContainer.GetCookies(this.BasicUrl);
            for (int i = 0; i < aux.Count; i++)
            {
                if (aux[i].Name == "csrftoken")
                {
                    this.CSRFTOKEN = aux[i].Value;
                }
            }
            this.Client.DefaultRequestHeaders.Add("X-CSRFToken", this.CSRFTOKEN);
        }

        /// <summary>
        /// Return password Encrypted for login.
        /// </summary>
        /// <param name="password">Password of account</param>
        /// <param name="providedTime">Time</param>
        /// <returns>Encrypted Password</returns>
        private string GetEncryptedPassword(string password, long? providedTime = null)
        {
            long time = providedTime ?? DateTime.UtcNow.ToUnixTime();
            return $"#PWD_INSTAGRAM:0:{time}:{password}";
        }

        public InstaResponse DoLogin(int atual = 1)
        {
            InstaResponse Ret = new InstaResponse
            {
                Response = "",
                Satus = 0
            };
            HttpResponseMessage response = this.Client.GetAsync(this.BasicUrl).Result;
            var sharedDate = WebHelper.GetJson(response.Content.ReadAsStringAsync().Result);
            var csrf_token = this.CSRFTOKEN;
            if (sharedDate != null)
            {
                var index = sharedDate.IndexOf("csrf_token\":\"");
                if (index > -1)
                {
                    csrf_token = sharedDate.Substring(index + 13, 32);
                }
            }
            this.CSRFTOKEN = csrf_token;
            this.Client.DefaultRequestHeaders.Remove("X-CSRFToken");
            this.Client.DefaultRequestHeaders.Add("X-CSRFToken", csrf_token);
            this.Client.DefaultRequestHeaders.Remove("X-IG-WWW-Claim");
            this.Client.DefaultRequestHeaders.Add("X-IG-WWW-Claim", "0");
            this.Client.DefaultRequestHeaders.Remove("Sec-Fetch-Mode");
            this.Client.DefaultRequestHeaders.Add("Sec-Fetch-Mode", "cors");
            this.Client.DefaultRequestHeaders.Remove("Referer");
            this.Client.DefaultRequestHeaders.Add("Referer", "https://www.instagram.com/");
            this.Client.DefaultRequestHeaders.Remove("X-ASBD-ID");
            this.Client.DefaultRequestHeaders.Add("X-ASBD-ID", "198387");
            this.Client.DefaultRequestHeaders.Remove("X-IG-App-ID");
            this.Client.DefaultRequestHeaders.Add("X-IG-App-ID", "936619743392459");
            var username = this.User.Username;
            var enc_password = GetEncryptedPassword(this.User.Password);
            var dict = new Dictionary<string, string>();
            dict.Add("username", username);
            dict.Add("enc_password", enc_password);
            var req = new HttpRequestMessage(HttpMethod.Post, this.BasicUrl + "/accounts/login/ajax/") { Content = new FormUrlEncodedContent(dict) };
            var res = this.Client.SendAsync(req).Result;
            if (res.IsSuccessStatusCode)
            {
                IEnumerable<string> headerValues = res.Headers.GetValues("x-ig-set-www-claim");
                this.X_IG_WWW_CLAIM = headerValues.FirstOrDefault();
                this.Client.DefaultRequestHeaders.Remove("X-IG-WWW-Claim");
                this.Client.DefaultRequestHeaders.Add("X-IG-WWW-Claim", this.X_IG_WWW_CLAIM);
                var aux = this.Handler.CookieContainer.GetCookies(this.BasicUrl);
                if (this.ListCookie == null)
                    this.ListCookie = new Dictionary<string, string>();
                for (int i = 0; i < aux.Count; i++)
                {
                    this.ListCookie.Add(aux[i].Name, aux[i].Value);
                    if (aux[i].Name == "csrftoken")
                    {
                        this.CSRFTOKEN = aux[i].Value;
                    }
                }
                csrf_token = this.CSRFTOKEN;
                this.Client.DefaultRequestHeaders.Remove("X-CSRFToken");
                this.Client.DefaultRequestHeaders.Add("X-CSRFToken", csrf_token);
                if (res.Content.ReadAsStringAsync().Result.IndexOf("\"authenticated\":true") > -1)
                {
                    Ret.Satus = 1;
                    Ret.Response = "Login realizado com sucesso";
                    this.Client.DefaultRequestHeaders.Add("X-IG-WWW-Claim", this.X_IG_WWW_CLAIM);
                    var aux3 = res.Content.ReadAsStringAsync().Result.Split('"');
                    this.UserID = long.Parse(aux3[5]);
                    var reqq = new HttpRequestMessage(HttpMethod.Get, this.BasicUrl);
                    var init = this.Client.SendAsync(reqq).Result;
                    if (init.IsSuccessStatusCode)
                    {
                        if (WebHelper.CanReadJson(init.Content.ReadAsStringAsync().Result))
                        {
                            var json = WebHelper.GetJson(init.Content.ReadAsStringAsync().Result);
                            this._shareddata = JsonConvert.DeserializeObject(json);
                            csrf_token = this._shareddata.config.csrf_token;
                            this.Client.DefaultRequestHeaders.Remove("X-CSRFToken");
                            this.Client.DefaultRequestHeaders.Add("X-CSRFToken", csrf_token);
                            this.CSRFTOKEN = csrf_token;
                        }
                    }
                    return Ret;
                }
                Ret.Satus = 0;
                Ret.Response = "Não foi possivel realizar o login";
            }
            else
            {
                if (res.Content.ReadAsStringAsync().Result.IndexOf("\"checkpoint_required\"") > -1)
                {
                    var serializado = res.Content.ReadAsStringAsync().Result;
                    dynamic dataJson = JsonConvert.DeserializeObject(serializado);
                    Challenge_URL = dataJson.checkpoint_url;
                    Ret.Satus = -2;
                    Ret.Response = "Conta com bloqueio ao logar";
                    return Ret;
                }
                else
                {
                    return DoLogin(atual++);
                }
            }
            return Ret;
        }

        public async Task<InstaResponseJson> GetUserProfileByUsernameAsync(string username, int atual = 1)
        {
            InstaResponseJson Ret = new InstaResponseJson
            {
                Response = "",
                Status = 0,
                Json = null
            };
            try
            {
                var req = new HttpRequestMessage(HttpMethod.Get, this.BasicUrl + $"{username.ToLower()}/?__a=1");
                var perfil = await this.Client.SendAsync(req);
                if (perfil.IsSuccessStatusCode)
                {
                    if ((await perfil.Content.ReadAsStringAsync()).IndexOf("\"biography\"") > -1)
                    {
                        var serializado = perfil.Content.ReadAsStringAsync().Result;
                        dynamic dataJson = JsonConvert.DeserializeObject(serializado);
                        Ret.Response = dataJson.graphql.user.id;
                        Ret.Status = 1;
                        Ret.Json = dataJson.graphql.user;
                    }
                    else
                    {
                        Ret.Response = await perfil.Content.ReadAsStringAsync();
                        Ret.Status = 0;
                    }
                }
                else
                {
                    var aux = await perfil.Content.ReadAsStringAsync();
                    if (aux.IndexOf("Go back to Instagram.") > -1)
                    {
                        await Task.Delay(1246);
                        if (atual < 3)
                            return await this.GetUserProfileByUsernameAsync(username, atual++);
                        Ret.Status = 0;
                        Ret.Response = "Usuario não encontrado";
                        return Ret;
                    }
                    else
                    {
                        if (aux.IndexOf("\"checkpoint_required\"") > -1)
                        {
                            Ret.Status = -2;
                            Ret.Response = aux;
                            dynamic challenge = JsonConvert.DeserializeObject(aux);
                            this.Challenge_URL = challenge.checkpoint_url;
                            return Ret;
                        }
                        else
                        {
                            if (aux.IndexOf("\"feedback_required\"") > -1)
                            {
                                Ret.Status = -3;
                                Ret.Response = aux;
                                return Ret;
                            }
                            else
                            {
                                Ret.Status = -4;
                                Ret.Response = aux;
                                return Ret;
                            }
                        }
                    }
                }
            }
            catch
            { }
            return Ret;
        }

        public async Task<InstaResponseJson> GetChallengeRequestByChallengeUrlAsync(int atual = 1)
        {
            InstaResponseJson Ret = new InstaResponseJson
            {
                Response = "Erro ao buscar challenge",
                Status = -1,
                Json = null
            };
            try
            {
                string url = "";
                if (this.Challenge_URL.IndexOf("instagram.com") > -1)
                {
                    url = $"{this.Challenge_URL}";
                }
                else
                {
                    if (this.Challenge_URL.StartsWith("/"))
                        url = $"https://instagram.com{this.Challenge_URL}";
                    else
                        url = $"https://instagram.com/{this.Challenge_URL}";
                }
                if (this.Challenge_URL.IndexOf("?") > -1)
                    url += "&__a=1";
                else
                    url += "?__a=1";
                var req = new HttpRequestMessage(HttpMethod.Get, url);
                var result = await this.Client.SendAsync(req);
                if (result.IsSuccessStatusCode)
                {
                    var serializado = await result.Content.ReadAsStringAsync();
                    dynamic dataJson = JsonConvert.DeserializeObject(serializado);
                    try
                    {
                        Ret.Response = dataJson.challengeType;
                        Ret.Status = 1;
                        Ret.Json = dataJson;
                        return Ret;
                    }
                    catch
                    {
                        Ret.Response = "Erro ao puxar o challenge: " + serializado;
                        Ret.Status = 2;
                        return Ret;
                    }
                }
                else
                {
                    var aux = await result.Content.ReadAsStringAsync();
                    if (aux.IndexOf("Go back to Instagram.") > -1 && atual < 3)
                    {
                        await Task.Delay(1246);
                        return await this.GetChallengeRequestByChallengeUrlAsync(atual++);
                    }
                    else
                    { }
                }
                return Ret;
            }
            catch (Exception err)
            {
                Ret.Response = err.Message;
                Ret.Status = -1;
            }
            return Ret;
        }

        public async Task<InstaResponseJson> GetChallengeRequestAsync(int atual = 1)
        {
            InstaResponseJson Ret = new InstaResponseJson
            {
                Response = "Erro ao buscar Challenge",
                Status = -1,
                Json = null
            };
            try
            {
                string url = "";
                if (this.Challenge_URL.IndexOf("instagram.com") > -1)
                {
                    url = $"{this.Challenge_URL}";
                }
                else
                {
                    if (this.Challenge_URL.StartsWith("/"))
                        url = $"https://instagram.com{this.Challenge_URL}";
                    else
                        url = $"https://instagram.com/{this.Challenge_URL}";
                }
                if (this.Challenge_URL.IndexOf("?") > -1)
                    url += "&__a=1";
                else
                    url += "?__a=1";
                var req = new HttpRequestMessage(HttpMethod.Get, url);
                var result = await this.Client.SendAsync(req);
                if (result.IsSuccessStatusCode)
                {
                    var serializado = await result.Content.ReadAsStringAsync();
                    dynamic dataJson = JsonConvert.DeserializeObject(serializado);
                    try
                    {
                        Ret.Response = dataJson.challengeType;
                        Ret.Status = 1;
                        Ret.Json = dataJson;
                        return Ret;
                    }
                    catch
                    {
                        Ret.Response = "Erro ao puxar o challenge: " + serializado;
                        Ret.Status = 2;
                        return Ret;
                    }
                }
                else
                {
                    var aux = await result.Content.ReadAsStringAsync();
                    if (aux.IndexOf("Go back to Instagram.") > -1 && atual < 3)
                    {
                        await Task.Delay(1246);
                        return await this.GetChallengeRequestAsync(atual++);
                    }
                    else
                    { }
                }
                return Ret;
            }
            catch (Exception err)
            {
                Ret.Response = err.Message;
                Ret.Status = -1;
            }
            return Ret;
        }

        public async Task<InstaResponse> ReplyChallengeByChoiceAsync(string choice, int atual = 1)
        {
            InstaResponse Ret = new InstaResponse
            {
                Response = "Erro ao responder ao challenge",
                Satus = 2
            };
            try
            {
                var dict = new Dictionary<string, string>();
                dict.Add("choice", choice);
                var req = new HttpRequestMessage(HttpMethod.Post, this.BasicUrl + $"challenge/") { Content = new FormUrlEncodedContent(dict) };
                var result = await this.Client.SendAsync(req);
                if (result.IsSuccessStatusCode)
                {
                    var serializado = await result.Content.ReadAsStringAsync();
                    dynamic dataJson = JsonConvert.DeserializeObject(serializado);
                    try
                    {
                        if (dataJson.status == "ok")
                        {
                            Ret.Response = "Sucesso";
                            Ret.Satus = 1;
                            return Ret;
                        }
                        else
                        {
                            Ret.Response = "Erro ao responder o challenge: " + serializado;
                            Ret.Satus = 2;
                            return Ret;
                        }
                    }
                    catch
                    {
                        Ret.Response = "Erro ao responder o challenge: " + serializado;
                        Ret.Satus = 2;
                        return Ret;
                    }
                }
                else
                {
                    var aux = await result.Content.ReadAsStringAsync();
                    if (aux.IndexOf("Go back to Instagram.") > -1)
                    {
                        Ret.Response = "Erro ao responder o challenge";
                        Ret.Satus = 2;
                        return Ret;
                    }
                    else
                    { }
                }
            }
            catch (Exception err)
            {
                Ret.Response = err.Message;
                Ret.Satus = -1;
            }
            return Ret;
        }

        public async Task<FriendshipRelation> GetFriendshipRelationByUsernameAsync(string username, int atual = 1)
        {
            FriendshipRelation Ret = new FriendshipRelation
            {
                Is_Complet = false,
                Is_Followed = false,
                Is_Following = false,
                Is_Private = false,
                PK = "",
                Response = "",
                Status = 0
            };
            try
            {
                var req = new HttpRequestMessage(HttpMethod.Get, this.BasicUrl + $"{username.ToLower()}/?__a=1");
                var perfil = await this.Client.SendAsync(req);
                if (perfil.IsSuccessStatusCode)
                {
                    if ((await perfil.Content.ReadAsStringAsync()).IndexOf("\"biography\"") > -1)
                    {
                        var serializado = await perfil.Content.ReadAsStringAsync();
                        dynamic dataJson = JsonConvert.DeserializeObject(serializado);
                        var user = dataJson.graphql.user;
                        Ret.Is_Following = user.followed_by_viewer;
                        Ret.Is_Followed = user.follows_viewer;
                        Ret.Is_Private = user.is_private;
                        Ret.PK = user.id;
                        Ret.Is_Complet = true;
                        Ret.Status = 1;
                        Ret.Response = "Sucesso";
                        return Ret;
                    }
                    else
                    {
                        var serializado = await perfil.Content.ReadAsStringAsync();
                        Ret.Is_Complet = false;
                        Ret.Response = serializado;
                        Ret.Status = -4;
                        return Ret;
                    }
                }
                else
                {
                    var aux = await perfil.Content.ReadAsStringAsync();
                    if (aux.IndexOf("Go back to Instagram.") > -1)
                    {
                        await Task.Delay(1246);
                        if (atual < 3)
                            return await this.GetFriendshipRelationByUsernameAsync(username, atual++);
                        Ret.Is_Complet = false;
                        Ret.Response = "Perfil não encontrado";
                        Ret.Status = 0;
                        return Ret;
                    }
                    else
                    {
                        if (aux.IndexOf("\"checkpoint_required\"") > -1)
                        {
                            Ret.Is_Complet = false;
                            Ret.Response = aux;
                            Ret.Status = -2;
                            dynamic challenge = JsonConvert.DeserializeObject(aux);
                            this.Challenge_URL = challenge.checkpoint_url;
                            return Ret;
                        }
                        else
                        {
                            if (aux.IndexOf("\"feedback_required\"") > -1)
                            {
                                Ret.Is_Complet = false;
                                Ret.Response = aux;
                                Ret.Status = -3;
                                return Ret;
                            }
                            else
                            {
                                Ret.Is_Complet = false;
                                Ret.Response = aux;
                                Ret.Status = -4;
                                return Ret;
                            }
                        }
                    }
                }
            }
            catch (Exception err)
            {
                Ret.Response = err.Message;
                Ret.Is_Complet = false;
                Ret.Status = -4;
            }
            return Ret;
        }

        public async Task<InstaResponse> GetUserBySearchBarAsync(string username, int atual = 1)
        {
            InstaResponse Ret = new InstaResponse
            {
                Response = "",
                Satus = 0
            };
            try
            {
                var req = new HttpRequestMessage(HttpMethod.Get, this.BasicUrl + $"/web/search/topsearch/?context=blended&query={username.ToLower()}&include_reel=false");
                var result = await this.Client.SendAsync(req);
                if (result.IsSuccessStatusCode)
                {
                    var serializado = await result.Content.ReadAsStringAsync();
                    dynamic userJson = JsonConvert.DeserializeObject(serializado);
                    try
                    {
                        for (int i = 0; i < userJson.users.Count; i++)
                        {
                            if (userJson.users[i].user.username == username.ToLower())
                            {
                                Ret.Response = userJson.users[0].user.pk;
                                Ret.Satus = 1;
                                return Ret;
                            }
                        }
                        Ret.Response = "Usuario não localizado";
                        Ret.Satus = 2;
                        return Ret;
                    }
                    catch
                    {
                        Ret.Response = "Usuario não localizado";
                        Ret.Satus = 2;
                        return Ret;
                    }
                }
                else
                {
                    var aux = await result.Content.ReadAsStringAsync();
                    if (aux.IndexOf("Go back to Instagram.") > -1 && atual < 4)
                    {
                        await Task.Delay(1246);
                        return await this.GetUserBySearchBarAsync(username, atual++);
                    }
                    else
                    {
                        if (aux.IndexOf("\"checkpoint_required\"") > -1)
                        {
                            Ret.Satus = -2;
                            Ret.Response = aux;
                            dynamic challenge = JsonConvert.DeserializeObject(aux);
                            this.Challenge_URL = challenge.checkpoint_url;
                            return Ret;
                        }
                        else
                        {
                            if (aux.IndexOf("\"feedback_required\"") > -1)
                            {
                                Ret.Satus = -3;
                                Ret.Response = aux;
                                return Ret;
                            }
                            else
                            {
                                Ret.Response = "Usuario não localizado";
                                Ret.Satus = 2;
                                return Ret;
                            }
                        }
                    }
                }
            }
            catch
            {
                Ret.Satus = -1;
                Ret.Response = "Erro na requisição";
                return Ret;
            }
        }

        public async Task<InstaResponse> GetUserIdByUsernameAsync(string username, int atual = 1)
        {
            InstaResponse Ret = new InstaResponse
            {
                Response = "",
                Satus = 0
            };
            try
            {
                var req = new HttpRequestMessage(HttpMethod.Get, this.BasicUrl + $"{username.ToLower()}/?__a=1");
                var perfil = await this.Client.SendAsync(req);
                if (perfil.IsSuccessStatusCode)
                {
                    if ((await perfil.Content.ReadAsStringAsync()).IndexOf("\"biography\"") > -1)
                    {
                        var serializado = perfil.Content.ReadAsStringAsync().Result;
                        dynamic dataJson = JsonConvert.DeserializeObject(serializado);
                        Ret.Response = dataJson.graphql.user.id;
                        Ret.Satus = 1;
                    }
                    else
                    {
                        Ret.Response = await perfil.Content.ReadAsStringAsync();
                        Ret.Satus = 0;
                    }
                }
                else
                {
                    var aux = await perfil.Content.ReadAsStringAsync();
                    if (aux.IndexOf("Go back to Instagram.") > -1)
                    {
                        await Task.Delay(1246);
                        if (atual < 3)
                            return await this.GetUserIdByUsernameAsync(username, atual++);
                        Ret.Satus = 0;
                        Ret.Response = "Usuario não encontrado";
                        return Ret;
                    }
                    else
                    {
                        if (aux.IndexOf("\"checkpoint_required\"") > -1)
                        {
                            Ret.Satus = -2;
                            Ret.Response = aux;
                            dynamic challenge = JsonConvert.DeserializeObject(aux);
                            this.Challenge_URL = challenge.checkpoint_url;
                            return Ret;
                        }
                        else
                        {
                            if (aux.IndexOf("\"feedback_required\"") > -1)
                            {
                                Ret.Satus = -3;
                                Ret.Response = aux;
                                return Ret;
                            }
                            else
                            {
                                Ret.Satus = -4;
                                Ret.Response = aux;
                                return Ret;
                            }
                        }
                    }
                }
            }
            catch
            { }
            return Ret;
        }

        public async Task<InstaResponse> FollowUserByIdAsync(string PK, int atual = 1)
        {
            InstaResponse Ret = new InstaResponse
            {
                Response = "",
                Satus = 0
            };
            try
            {
                var req = new HttpRequestMessage(HttpMethod.Post, this.BasicUrl + $"web/friendships/{PK}/follow/");
                var result = await this.Client.SendAsync(req);
                if (result.IsSuccessStatusCode)
                {
                    var serializado = await result.Content.ReadAsStringAsync();
                    dynamic userJson = JsonConvert.DeserializeObject(serializado);
                    try
                    {
                        if (userJson.status == "ok")
                        {
                            Ret.Response = "Sucesso";
                            Ret.Satus = 1;
                            return Ret;
                        }
                        Ret.Response = serializado;
                        Ret.Satus = 2;
                        return Ret;
                    }
                    catch
                    {
                        Ret.Response = "Usuario não localizado";
                        Ret.Satus = 2;
                        return Ret;
                    }
                }
                else
                {
                    var aux = await result.Content.ReadAsStringAsync();
                    if (aux.IndexOf("Go back to Instagram.") > -1 && atual < 3)
                    {
                        await Task.Delay(1246);
                        return await this.FollowUserByIdAsync(PK, atual++);
                    }
                    else
                    {
                        if (aux.IndexOf("\"checkpoint_required\"") > -1)
                        {
                            Ret.Satus = -2;
                            Ret.Response = aux;
                            dynamic challenge = JsonConvert.DeserializeObject(aux);
                            this.Challenge_URL = challenge.checkpoint_url;
                            return Ret;
                        }
                        else
                        {
                            if (aux.IndexOf("\"feedback_required\"") > -1)
                            {
                                Ret.Satus = -3;
                                Ret.Response = aux;
                                return Ret;
                            }
                            else
                            {
                                Ret.Response = "Usuario não localizado";
                                Ret.Satus = 2;
                                return Ret;
                            }
                        }
                    }
                }
            }
            catch (Exception err)
            {
                Ret.Satus = -4;
                Ret.Response = err.Message;
                return Ret;
            }
        }

        public async Task<InstaResponse> UnfollowUserByIdAsync(string PK, int atual = 1)
        {
            InstaResponse Ret = new InstaResponse
            {
                Response = "",
                Satus = 0
            };
            try
            {
                var req = new HttpRequestMessage(HttpMethod.Post, this.BasicUrl + $"web/friendships/{PK}/unfollow/");
                var result = await this.Client.SendAsync(req);
                if (result.IsSuccessStatusCode)
                {
                    var serializado = await result.Content.ReadAsStringAsync();
                    dynamic userJson = JsonConvert.DeserializeObject(serializado);
                    try
                    {
                        if (userJson.status == "ok")
                        {
                            Ret.Response = "Sucesso";
                            Ret.Satus = 1;
                            return Ret;
                        }
                        Ret.Response = serializado;
                        Ret.Satus = 2;
                        return Ret;
                    }
                    catch
                    {
                        Ret.Response = "Usuario não localizado";
                        Ret.Satus = 2;
                        return Ret;
                    }
                }
                else
                {
                    var aux = await result.Content.ReadAsStringAsync();
                    if (aux.IndexOf("Go back to Instagram.") > -1 && atual < 4)
                    {
                        await Task.Delay(1246);
                        return await this.UnfollowUserByIdAsync(PK, atual++);
                    }
                    else
                    {
                        if (aux.IndexOf("\"checkpoint_required\"") > -1)
                        {
                            Ret.Satus = -2;
                            Ret.Response = aux;
                            dynamic challenge = JsonConvert.DeserializeObject(aux);
                            this.Challenge_URL = challenge.checkpoint_url;
                            return Ret;
                        }
                        else
                        {
                            if (aux.IndexOf("\"feedback_required\"") > -1)
                            {
                                Ret.Satus = -3;
                                Ret.Response = aux;
                                return Ret;
                            }
                            else
                            {
                                Ret.Response = "Usuario não localizado";
                                Ret.Satus = 2;
                                return Ret;
                            }
                        }
                    }
                }
            }
            catch (Exception err)
            {
                Ret.Satus = -4;
                Ret.Response = err.Message;
                return Ret;
            }
        }

        public async Task<InstaResponseJson> GetSuspiciousLoginAsync(int atual = 1)
        {
            InstaResponseJson Ret = new InstaResponseJson
            {
                Response = "",
                Status = 0,
                Json = null
            };
            try
            {
                var req = new HttpRequestMessage(HttpMethod.Get, this.BasicUrl + "session/login_activity/?__a=1");
                var result = await this.Client.SendAsync(req);
                if (result.IsSuccessStatusCode)
                {
                    var serializado = await result.Content.ReadAsStringAsync();
                    dynamic data = JsonConvert.DeserializeObject(serializado);
                    try
                    {
                        if (data.data.suspicious_logins != null)
                        {
                            Ret.Response = "Sucesso";
                            Ret.Status = 1;
                            Ret.Json = data.data.suspicious_logins;
                            return Ret;
                        }
                        Ret.Response = serializado;
                        Ret.Status = 2;
                        return Ret;
                    }
                    catch
                    {
                        Ret.Response = "Não foi possivel pegar os dados de login";
                        Ret.Status = 2;
                        return Ret;
                    }
                }
                else
                {
                    var aux = await result.Content.ReadAsStringAsync();
                    if (aux.IndexOf("Go back to Instagram.") > -1 && atual < 4)
                    {
                        await Task.Delay(1246);
                        return await this.GetSuspiciousLoginAsync(atual++);
                    }
                    else
                    {
                        if (aux.IndexOf("\"checkpoint_required\"") > -1)
                        {
                            Ret.Status = -2;
                            Ret.Response = aux;
                            dynamic challenge = JsonConvert.DeserializeObject(aux);
                            this.Challenge_URL = challenge.checkpoint_url;
                            return Ret;
                        }
                        else
                        {
                            if (aux.IndexOf("\"feedback_required\"") > -1)
                            {
                                Ret.Status = -3;
                                Ret.Response = aux;
                                return Ret;
                            }
                            else
                            {
                                Ret.Response = "Não foi possivel pegar os dados de login";
                                Ret.Status = 2;
                                return Ret;
                            }
                        }
                    }
                }
            }
            catch (Exception err)
            {
                Ret.Status = -4;
                Ret.Response = err.Message;
                return Ret;
            }
        }

        public async Task<InstaResponseJson> GetMyProfileAsync(int atual = 1)
        {
            InstaResponseJson Ret = new InstaResponseJson
            {
                Response = "",
                Status = 0,
                Json = null
            };
            try
            {
                var req = new HttpRequestMessage(HttpMethod.Get, this.BasicUrl + "accounts/edit/?__a=1");
                var result = await this.Client.SendAsync(req);
                if (result.IsSuccessStatusCode)
                {
                    var serializado = await result.Content.ReadAsStringAsync();
                    dynamic userJson = JsonConvert.DeserializeObject(serializado);
                    try
                    {
                        if (userJson.form_data.username == this.User.Username.ToLower())
                        {
                            Ret.Response = "Sucesso";
                            Ret.Status = 1;
                            Ret.Json = userJson.form_data;
                            return Ret;
                        }
                        Ret.Response = serializado;
                        Ret.Status = 2;
                        return Ret;
                    }
                    catch
                    {
                        Ret.Response = "Erro ao pegar dados do perfil";
                        Ret.Status = 2;
                        return Ret;
                    }
                }
                else
                {
                    var aux = await result.Content.ReadAsStringAsync();
                    if (aux.IndexOf("Go back to Instagram.") > -1 && atual < 4)
                    {
                        await Task.Delay(1246);
                        return await this.GetMyProfileAsync(atual++);
                    }
                    else
                    {
                        if (aux.IndexOf("\"checkpoint_required\"") > -1)
                        {
                            Ret.Status = -2;
                            Ret.Response = aux;
                            dynamic challenge = JsonConvert.DeserializeObject(aux);
                            this.Challenge_URL = challenge.checkpoint_url;
                            return Ret;
                        }
                        else
                        {
                            if (aux.IndexOf("\"feedback_required\"") > -1)
                            {
                                Ret.Status = -3;
                                Ret.Response = aux;
                                return Ret;
                            }
                            else
                            {
                                Ret.Response = "Erro ao pegar dados do perfil";
                                Ret.Status = 2;
                                return Ret;
                            }
                        }
                    }
                }
            }
            catch (Exception err)
            {
                Ret.Status = -1;
                Ret.Response = err.Message;
                return Ret;
            }
        }

        public async Task<InstaResponse> UpdateProfileAsync(string name = "", string email = "", string phone = "", int gender = 2, string bio = "", string url = "", bool similar = false, int atual = 1)
        {
            InstaResponse Ret = new InstaResponse
            {
                Response = "",
                Satus = 0
            };
            var atual_profile = await this.GetMyProfileAsync();
            if (atual_profile.Status == 1)
            {
                try
                {
                    var dict = new Dictionary<string, string>();
                    dict.Add("first_name", name != "" ? name : atual_profile.Json.first_name);
                    dict.Add("email", email != "" ? email : atual_profile.Json.email);
                    dict.Add("username", this.User.Username.ToLower());
                    dict.Add("phone_number", phone != "" ? phone : atual_profile.Json.phone_number);
                    dict.Add("gender", gender.ToString());
                    dict.Add("biography", bio != "" ? bio : atual_profile.Json.biography);
                    dict.Add("external_url", url != "" ? url : atual_profile.Json.external_url);
                    dict.Add("chaining_enabled", similar.ToString());
                    var req = new HttpRequestMessage(HttpMethod.Post, this.BasicUrl + "accounts/edit/") { Content = new FormUrlEncodedContent(dict) };
                    var result = await this.Client.SendAsync(req);
                    if (result.IsSuccessStatusCode)
                    {
                        var serializado = await result.Content.ReadAsStringAsync();
                        dynamic dataJson = JsonConvert.DeserializeObject(serializado);
                        if (dataJson.status == "ok")
                        {
                            Ret.Response = "Sucesso";
                            Ret.Satus = 1;
                            return Ret;
                        }
                        else
                        {
                            Ret.Response = dataJson.status;
                            Ret.Satus = 0;
                            return Ret;
                        }
                    }
                    else
                    {
                        var aux = await result.Content.ReadAsStringAsync();
                        if (aux.IndexOf("Go back to Instagram.") > -1 && atual < 4)
                        {
                            await Task.Delay(1246);
                            return await this.UpdateProfileAsync(name, email, phone, gender, bio, url, similar, atual++);
                        }
                        else
                        {
                            if (aux.IndexOf("\"checkpoint_required\"") > -1)
                            {
                                Ret.Satus = -2;
                                Ret.Response = aux;
                                dynamic challenge = JsonConvert.DeserializeObject(aux);
                                this.Challenge_URL = challenge.checkpoint_url;
                                return Ret;
                            }
                            else
                            {
                                if (aux.IndexOf("\"feedback_required\"") > -1)
                                {
                                    Ret.Satus = -3;
                                    Ret.Response = aux;
                                    return Ret;
                                }
                                else
                                {
                                    Ret.Satus = -4;
                                    Ret.Response = aux;
                                    return Ret;
                                }
                            }
                        }
                    }
                }
                catch (Exception err)
                {
                    Ret.Response = err.Message;
                    Ret.Satus = -1;
                    return Ret;
                }
            }
            else
            {
                Ret.Response = "Não foi possivel recuperar o perfil atual";
                return Ret;
            }
        }

        public async Task<InstaResponse> AllowSuspiciosLoginByIdAsync(string ID, int atual = 1)
        {
            InstaResponse Ret = new InstaResponse
            {
                Response = "",
                Satus = 0
            };
            try
            {
                var dict = new Dictionary<string, string>();
                dict.Add("login_id", ID);
                var req = new HttpRequestMessage(HttpMethod.Post, this.BasicUrl + "session/login_activity/avow_login/") { Content = new FormUrlEncodedContent(dict) };
                var result = await this.Client.SendAsync(req);
                if (result.IsSuccessStatusCode)
                {
                    Ret.Response = "Sucesso";
                    Ret.Satus = 1;
                    return Ret;
                }
                else
                {
                    var aux = await result.Content.ReadAsStringAsync();
                    if (aux.IndexOf("Go back to Instagram.") > -1 && atual < 4)
                    {
                        await Task.Delay(1246);
                        return await this.AllowSuspiciosLoginByIdAsync(ID, atual++);
                    }
                    else
                    {
                        if (aux.IndexOf("\"checkpoint_required\"") > -1)
                        {
                            Ret.Satus = -2;
                            Ret.Response = aux;
                            dynamic challenge = JsonConvert.DeserializeObject(aux);
                            this.Challenge_URL = challenge.checkpoint_url;
                            return Ret;
                        }
                        else
                        {
                            if (aux.IndexOf("\"feedback_required\"") > -1)
                            {
                                Ret.Satus = -3;
                                Ret.Response = aux;
                                return Ret;
                            }
                            else
                            {
                                Ret.Satus = -4;
                                Ret.Response = aux;
                                return Ret;
                            }
                        }
                    }
                }
            }
            catch (Exception err)
            {
                Ret.Satus = -1;
                Ret.Response = err.Message;
                return Ret;
            }
        }

        public async Task<MediaRelation> GetMediaRelationByShortcodeAsync(string shortcode, int atual = 1)
        {
            MediaRelation Ret = new MediaRelation
            {
                Is_Complet = false,
                Is_PrivateOwner = false,
                Is_FollowingOwner = false,
                Is_Liked = false,
                MediaID = "",
                MediaShortcode = shortcode,
                OwnerPK = "",
                OwnerUsername = "",
                Response = ""
            };
            try
            {
                var req = new HttpRequestMessage(HttpMethod.Get, this.BasicUrl + $"p/{shortcode}/?__a=1");
                var res = await this.Client.SendAsync(req);
                if (res.IsSuccessStatusCode)
                {
                    if ((await res.Content.ReadAsStringAsync()).IndexOf("\"shortcode_media\"") > -1)
                    {
                        var serializado = await res.Content.ReadAsStringAsync();
                        dynamic dataJson = JsonConvert.DeserializeObject(serializado);
                        var data = dataJson.graphql.shortcode_media;
                        Ret.Is_PrivateOwner = data.owner.is_private;
                        Ret.Is_FollowingOwner = data.owner.followed_by_viewer;
                        Ret.Is_Liked = data.viewer_has_liked;
                        Ret.OwnerPK = data.owner.id;
                        Ret.OwnerUsername = data.owner.username;
                        Ret.MediaID = data.id;
                        Ret.Is_Complet = true;
                        Ret.Response = "Sucesso";
                        Ret.Status = 1;
                        return Ret;
                    }
                    else
                    {
                        var serializado = await res.Content.ReadAsStringAsync();
                        Ret.Is_Complet = false;
                        Ret.Response = serializado;
                        return Ret;
                    }
                }
                else
                {
                    var aux = await res.Content.ReadAsStringAsync();
                    if (aux.IndexOf("Go back to Instagram.") > -1 && atual < 3)
                    {
                        await Task.Delay(1246);
                        return await this.GetMediaRelationByShortcodeAsync(shortcode, atual++);
                    }
                    else
                    {
                        if (aux.IndexOf("\"checkpoint_required\"") > -1)
                        {
                            Ret.Status = -2;
                            Ret.Is_Complet = false;
                            Ret.Response = aux;
                            dynamic challenge = JsonConvert.DeserializeObject(aux);
                            this.Challenge_URL = challenge.checkpoint_url;
                            return Ret;
                        }
                        else
                        {
                            if (aux.IndexOf("\"feedback_required\"") > -1)
                            {
                                Ret.Status = -3;
                                Ret.Is_Complet = false;
                                Ret.Response = aux;
                                return Ret;
                            }
                            else
                            {
                                Ret.Status = -4;
                                Ret.Is_Complet = false;
                                Ret.Response = aux;
                                return Ret;
                            }
                        }
                    }
                }
            }
            catch (Exception err)
            {
                Ret.Status = -1;
                Ret.Response = err.Message;
                Ret.Is_Complet = false;
                return Ret;
            }
        }

        public async Task<InstaResponse> LikeMediaByIdAsync(string mediaID, int atual = 1)
        {
            InstaResponse Ret = new InstaResponse
            {
                Response = "",
                Satus = 0
            };
            try
            {
                var req = new HttpRequestMessage(HttpMethod.Post, this.BasicUrl + $"web/likes/{mediaID}/like/");
                var result = await this.Client.SendAsync(req);
                if (result.IsSuccessStatusCode)
                {
                    var serializado = await result.Content.ReadAsStringAsync();
                    dynamic dataJson = JsonConvert.DeserializeObject(serializado);
                    try
                    {
                        if (dataJson.status == "ok")
                        {
                            Ret.Response = "Sucesso";
                            Ret.Satus = 1;
                            return Ret;
                        }
                        Ret.Response = serializado;
                        Ret.Satus = 2;
                        return Ret;
                    }
                    catch
                    {
                        Ret.Response = "Erro ao curtir a publicação: " + serializado;
                        Ret.Satus = 2;
                        return Ret;
                    }
                }
                else
                {
                    var aux = await result.Content.ReadAsStringAsync();
                    if (aux.IndexOf("Go back to Instagram.") > -1 && atual < 4)
                    {
                        await Task.Delay(1246);
                        return await this.LikeMediaByIdAsync(mediaID, atual++);
                    }
                    else
                    {
                        if (aux.IndexOf("\"checkpoint_required\"") > -1)
                        {
                            Ret.Satus = -2;
                            Ret.Response = "Conta com bloqueio";
                            dynamic challenge = JsonConvert.DeserializeObject(aux);
                            this.Challenge_URL = challenge.checkpoint_url;
                            return Ret;
                        }
                        else
                        {
                            if (aux.IndexOf("\"checkpoint_required\"") > -1)
                            {
                                Ret.Satus = -2;
                                Ret.Response = aux;
                                dynamic challenge = JsonConvert.DeserializeObject(aux);
                                this.Challenge_URL = challenge.checkpoint_url;
                                return Ret;
                            }
                            else
                            {
                                if (aux.IndexOf("\"feedback_required\"") > -1)
                                {
                                    Ret.Satus = -3;
                                    Ret.Response = aux;
                                    return Ret;
                                }
                                else
                                {
                                    Ret.Satus = -4;
                                    Ret.Response = aux;
                                    return Ret;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception err)
            {
                Ret.Response = err.Message;
                Ret.Satus = -1;
            }
            return Ret;
        }

        public async Task<InstaResponse> UnlikeMediaByIdAsync(string mediaID, int atual = 1)
        {
            InstaResponse Ret = new InstaResponse
            {
                Response = "",
                Satus = 0
            };
            try
            {
                var req = new HttpRequestMessage(HttpMethod.Post, this.BasicUrl + $"web/likes/{mediaID}/unlike/");
                var result = await this.Client.SendAsync(req);
                if (result.IsSuccessStatusCode)
                {
                    var serializado = await result.Content.ReadAsStringAsync();
                    dynamic dataJson = JsonConvert.DeserializeObject(serializado);
                    try
                    {
                        if (dataJson.status == "ok")
                        {
                            Ret.Response = "Sucesso";
                            Ret.Satus = 1;
                            return Ret;
                        }
                        Ret.Response = serializado;
                        Ret.Satus = 2;
                        return Ret;
                    }
                    catch
                    {
                        Ret.Response = "Erro ao deixar de curtir a publicação: " + serializado;
                        Ret.Satus = 2;
                        return Ret;
                    }
                }
                else
                {
                    var aux = await result.Content.ReadAsStringAsync();
                    if (aux.IndexOf("Go back to Instagram.") > -1 && atual < 4)
                    {
                        await Task.Delay(1246);
                        return await this.UnlikeMediaByIdAsync(mediaID, atual++);
                    }
                    else
                    {
                        if (aux.IndexOf("\"checkpoint_required\"") > -1)
                        {
                            Ret.Satus = -2;
                            Ret.Response = aux;
                            dynamic challenge = JsonConvert.DeserializeObject(aux);
                            this.Challenge_URL = challenge.checkpoint_url;
                            return Ret;
                        }
                        else
                        {
                            if (aux.IndexOf("\"feedback_required\"") > -1)
                            {
                                Ret.Satus = -3;
                                Ret.Response = aux;
                                return Ret;
                            }
                            else
                            {
                                Ret.Satus = -4;
                                Ret.Response = aux;
                                return Ret;
                            }
                        }
                    }
                }
            }
            catch (Exception err)
            {
                Ret.Response = err.Message;
                Ret.Satus = -1;
            }
            return Ret;
        }

        public async Task<InstaResponseJson> CommentMediaByIdAsync(string mediaID, string comentario, int atual = 1)
        {
            InstaResponseJson Ret = new InstaResponseJson
            {
                Response = "",
                Status = 0,
                Json = null
            };
            try
            {
                var dict = new Dictionary<string, string>();
                dict.Add("comment_text", comentario);
                dict.Add("replied_to_comment_id", "");
                var req = new HttpRequestMessage(HttpMethod.Post, this.BasicUrl + $"web/comments/{mediaID}/add/") { Content = new FormUrlEncodedContent(dict) };
                var result = await this.Client.SendAsync(req);
                if (result.IsSuccessStatusCode)
                {
                    var serializado = await result.Content.ReadAsStringAsync();
                    dynamic dataJson = JsonConvert.DeserializeObject(serializado);
                    try
                    {
                        if (dataJson.status == "ok")
                        {
                            Ret.Response = "Sucesso";
                            Ret.Status = 1;
                            Ret.Json = dataJson;
                            return Ret;
                        }
                        Ret.Response = serializado;
                        Ret.Status = 2;
                        return Ret;
                    }
                    catch
                    {
                        Ret.Response = "Erro ao comentar a publicação: " + serializado;
                        Ret.Status = 2;
                        return Ret;
                    }
                }
                else
                {
                    var aux = await result.Content.ReadAsStringAsync();
                    if (aux.IndexOf("Go back to Instagram.") > -1 && atual < 4)
                    {
                        await Task.Delay(1246);
                        return await this.CommentMediaByIdAsync(mediaID, comentario, atual++);
                    }
                    else
                    {
                        if (aux.IndexOf("\"checkpoint_required\"") > -1)
                        {
                            Ret.Status = -2;
                            Ret.Response = aux;
                            dynamic challenge = JsonConvert.DeserializeObject(aux);
                            this.Challenge_URL = challenge.checkpoint_url;
                            return Ret;
                        }
                        else
                        {
                            if (aux.IndexOf("\"feedback_required\"") > -1)
                            {
                                Ret.Status = -3;
                                Ret.Response = aux;
                                return Ret;
                            }
                            else
                            {
                                Ret.Status = -4;
                                Ret.Response = aux;
                                return Ret;
                            }
                        }
                    }
                }
            }
            catch (Exception err)
            {
                Ret.Response = err.Message;
                Ret.Status = -1;
            }
            return Ret;
        }

    }
}
