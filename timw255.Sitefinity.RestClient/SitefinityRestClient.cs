using RestSharp;
using RestSharp.Deserializers;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using timw255.Sitefinity.RestClient.Exceptions;
using timw255.Sitefinity.RestClient.SitefinityClient.Exceptions;

namespace timw255.Sitefinity.RestClient
{
    public class SitefinityRestClient : IDisposable
    {
        private RestSharp.RestClient _restClient;
        private string _baseUrl;
        private string _username;
        private string _password;
        private DateTime expiresOn;

        public SitefinityRestClient(string username, string password, string baseUrl)
        {
            this._username = username;
            this._password = password;
            this._baseUrl = String.Concat(baseUrl.TrimEnd('/'), "/");

            Uri uriResult;
            Uri.TryCreate(this._baseUrl, UriKind.Absolute, out uriResult);

            this._restClient = new RestSharp.RestClient(uriResult);
            this._restClient.CookieContainer = new CookieContainer();
            this._restClient.ClearHandlers();
            this._restClient.AddHandler("application/json", new JsonDeserializer());

            this.SignIn();
        }

        protected internal IRestResponse ExecuteRequest(IRestRequest request, bool isRetry = false)
        {
            IRestResponse response = _restClient.Execute(request);

            if (response.StatusCode == HttpStatusCode.Forbidden || response.StatusCode == HttpStatusCode.Unauthorized)
            {
                if (isRetry)
                {
                    throw new SitefinityException("User already logged in");
                }
                else
                {
                    SelfLogout();
                    ExecuteRequest(request, true);
                }
            }

            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw new InvalidRequestException(response.StatusDescription);
            }

            return response;
        }

        private void SignIn()
        {
            RestRequest request = new RestRequest("Sitefinity/Authenticate", Method.GET);

            IRestResponse response = _restClient.Execute(request);

            switch (response.StatusCode)
            {
                case HttpStatusCode.OK:

                    var formData = String.Format("wrap_name={0}&wrap_password={1}", _username, _password);
                    var bytes = Encoding.UTF8.GetBytes(formData);
                    string strResponse;
                    WebHeaderCollection headers;
                    var responseCode = Request(_restClient.BaseUrl + "Sitefinity/Authenticate/SWT", out strResponse, out headers, bytes, "POST", "application/x-www-form-urlencoded");
                   
                    if (responseCode == HttpStatusCode.OK)
                    {
                        // we expect WRAP formatted response which is the same as query string
                        var nameValueColl = HttpUtility.ParseQueryString(strResponse);
                        var bootstrapToken = nameValueColl["wrap_access_token"];
                        expiresOn = DateTime.Now + TimeSpan.FromSeconds(int.Parse(nameValueColl["wrap_access_token_expires_in"]));
                        _restClient.AddDefaultHeader("Authorization", String.Format("WRAP access_token=\"{0}\"", bootstrapToken));

                    }
                    if (responseCode == HttpStatusCode.Unauthorized)
                    {
                        // This means wrong credentials were submitted

                        throw new Exception("Wrong credential");
                    }

                    /*
                    request = new RestRequest("Sitefinity/Authenticate/SWT?realm={realm}&redirect_uri={redirectUri}&deflate=true", Method.POST);

                    request.AddUrlSegment("realm", _baseUrl);
                    request.AddUrlSegment("redirectUri", "/Sitefinity");

                    request.AddParameter("wrap_name", _username, ParameterType.GetOrPost);
                    request.AddParameter("wrap_password", _password, ParameterType.GetOrPost);
                    request.AddParameter("sf_persistent", "true", ParameterType.GetOrPost);

                    response = _restClient.Execute(request);

                    
                    switch (response.StatusCode)
                    {
                        case HttpStatusCode.OK:
                            if (response.ResponseUri.AbsolutePath == "/Sitefinity/SignOut/selflogout")
                            {
                                SelfLogout();
                            }
                            break;
                        case HttpStatusCode.Unauthorized:
                            throw new SitefinityException("Invalid username or password");
                        default:
                            break;
                    }*/
                    break;
                case HttpStatusCode.Redirect:
                    throw new NotImplementedException("External STS not supported");
                default:
                    throw new Exception("Unable get Sitefinity/Authenticate Page");
            }
        }

        private void SelfLogout()
        {
            RestRequest request = new RestRequest("Sitefinity/SignOut/selflogout?ReturnUrl=%2fSitefinity%2fdashboard", Method.POST);

            request.AddParameter("__EVENTTARGET", "ctl04$ctl00$ctl00$ctl00$ctl00$ctl00$selfLogoutButton");
            request.AddParameter("__EVENTARGUMENT", "");

            _restClient.Execute(request);
            return;
        }

        private void SignOut()
        {
            RestRequest request = new RestRequest("Sitefinity/SignOut?sts_signout=true", Method.GET);

            ExecuteRequest(request);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~SitefinityRestClient() 
        {
            Dispose(false);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing) 
            {
                this.SignOut();
            }
        }


        public HttpStatusCode Request(string url, out string responseBody, out WebHeaderCollection responseHeaders, byte[] data = null, string httpMethod = "GET", string contentType = "", NameValueCollection requestHeaders = null)
        {
            // Create and set the request object
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = httpMethod;
            request.ContentType = contentType;
            request.CookieContainer = this._restClient.CookieContainer;
            if (requestHeaders != null)
                request.Headers.Add(requestHeaders);

            request.KeepAlive = true;
            //if(contentType == "application/json")
            //    request.Headers.Add("Content-Type", contentType);

            // Add cookies if there are any

            if (data != null)
            {
                request.ContentLength = data.Length;
                // Send the data to the request stream
                using (var writer = request.GetRequestStream())
                {
                    writer.Write(data, 0, data.Length);
                }
            }

            // Invoke the method and return the response.
            HttpStatusCode statusCode;
            HttpWebResponse response = null;

            try
            {
                response = (HttpWebResponse)request.GetResponse();
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    response = (HttpWebResponse)ex.Response;
                }
            }
            finally
            {
                if (response != null)
                {
                    // Store the cookies from the response for the current session.
                    var cookies = response.Cookies;

                    foreach (System.Net.Cookie cookie in response.Cookies)
                        this._restClient.CookieContainer.Add(cookie);
                    // Read the response
                    using (var reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
                    {
                        responseBody = reader.ReadToEnd();
                    }
                    responseHeaders = response.Headers;
                    statusCode = response.StatusCode;
                    response.Close();
                }
                else
                {
                    statusCode = HttpStatusCode.InternalServerError;
                    responseBody = "";
                    responseHeaders = null;
                }
            }
            //SignOut();
            return statusCode;
        }
    }
}
