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
    public class ConfigPoliciesServiceWrapper : ServiceWrapper
    {
        public ConfigPoliciesServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Configuration/ConfigPolicies.svc/";
            this.SF = sf;
        }

        //[WebInvoke(Method="PUT", UriTemplate="{policyHandlerName}/{policyName}/?provider={provider}", ResponseFormat=WebMessageFormat.Json)]
        public bool CreatePolicy(string policyHandlerName, string policyName, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("{policyHandlerName}/{policyName}/?provider={provider}"), Method.PUT);

            request.AddUrlSegment("policyHandlerName", policyHandlerName);
            request.AddUrlSegment("policyName", policyName);
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method="DELETE", UriTemplate="{policyHandlerName}/{policyName}/?provider={provider}", ResponseFormat=WebMessageFormat.Json)]
        public bool DeletePolicy(string policyHandlerName, string policyName, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("{policyHandlerName}/{policyName}/?provider={provider}"), Method.DELETE);

            request.AddUrlSegment("policyHandlerName", policyHandlerName);
            request.AddUrlSegment("policyName", policyName);
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<bool>(request);
        }

        //[WebGet(UriTemplate="{policyHandlerName=null}/?provider={provider}&sort={sort}&skip={skip}&take={take}&filter={filter}", ResponseFormat=WebMessageFormat.Json)]
        public CollectionContext<PolicyItem> GetPolicies(string policyHandlerName, string provider, string sort, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("{policyHandlerName}/?provider={provider}&sort={sort}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("policyHandlerName", policyHandlerName);
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sort", sort);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<PolicyItem>>(request);
        }
    }
}
