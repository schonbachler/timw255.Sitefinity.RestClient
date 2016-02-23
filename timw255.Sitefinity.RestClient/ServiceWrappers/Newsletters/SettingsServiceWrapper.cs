﻿using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using timw255.Sitefinity.RestClient.Model;

namespace timw255.Sitefinity.RestClient.ServiceWrappers.Newsletters
{
    public class SettingsServiceWrapper : ServiceWrapper
    {
        public SettingsServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Newsletters/Settings.svc/";
            this.SF = sf;
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/pop3test/")]
        public string TestPop3Server(Pop3SettingsViewModel settings)
        {
            var request = new RestRequest(this.GetServiceUrl("/pop3test/"), Method.POST);

            request.AddParameter("application/json", SerializeObject(settings), ParameterType.RequestBody);

            return ExecuteRequest<string>(request);
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/smtptest/")]
        public string TestSmtpServer(SmtpSettingsViewModel settings)
        {
            var request = new RestRequest(this.GetServiceUrl("/smtptest/"), Method.POST);

            request.AddParameter("application/json", SerializeObject(settings), ParameterType.RequestBody);

            return ExecuteRequest<string>(request);
        }
    }
}
