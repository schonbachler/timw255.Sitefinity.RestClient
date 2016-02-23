﻿using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using timw255.Sitefinity.RestClient.Model;

namespace timw255.Sitefinity.RestClient.ServiceWrappers
{
    public class SitefinityProjectServiceWrapper : ServiceWrapper
    {
        public SitefinityProjectServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/SitefinityProject.svc/";
            this.SF = sf;
        }

        //[WebGet(UriTemplate = "/All")]
        public ProjectInfo GetAll()
        {
            var request = new RestRequest(this.GetServiceUrl("/All"), Method.GET);

            return ExecuteRequest<ProjectInfo>(request);
        }

        //[WebGet(UriTemplate = "/Name")]
        public string GetName()
        {
            var request = new RestRequest(this.GetServiceUrl("/Name"), Method.GET);

            return ExecuteRequest<string>(request);
        }

        //[WebGet(UriTemplate = "/SfVersion")]
        public string GetSfVersion()
        {
            var request = new RestRequest(this.GetServiceUrl("/SfVersion"), Method.GET);

            return ExecuteRequest<string>(request);
        }

        //[WebGet(UriTemplate = "/Version")]
        public string GetVersion()
        {
            var request = new RestRequest(this.GetServiceUrl("/Version"), Method.GET);

            return ExecuteRequest<string>(request);
        }
    }
}
