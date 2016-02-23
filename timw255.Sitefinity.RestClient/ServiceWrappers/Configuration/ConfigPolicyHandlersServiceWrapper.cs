﻿using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using timw255.Sitefinity.RestClient.Model;

namespace timw255.Sitefinity.RestClient.ServiceWrappers.Configuration
{
    public class ConfigPolicyHandlersServiceWrapper : ServiceWrapper
    {
        public ConfigPolicyHandlersServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Configuration/ConfigPolicyHandlers.svc/";
            this.SF = sf;
        }

        //[WebGet(UriTemplate="/?sort={sort}&skip={skip}&take={take}&filter={filter}&provider={provider}", ResponseFormat=WebMessageFormat.Json)]
        public CollectionContext<UIConfigPolicyHandler> GetConfigHandlers(string sort, int skip, int take, string filter, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/?sort={sort}&skip={skip}&take={take}&filter={filter}&provider={provider}"), Method.GET);

            request.AddUrlSegment("sort", sort);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<CollectionContext<UIConfigPolicyHandler>>(request);
        }
    }
}
