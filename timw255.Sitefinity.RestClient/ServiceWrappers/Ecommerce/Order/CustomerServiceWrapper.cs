﻿using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using timw255.Sitefinity.RestClient.Model;

namespace timw255.Sitefinity.RestClient.ServiceWrappers.Ecommerce.Order
{
    public class CustomerServiceWrapper : ServiceWrapper
    {
        public CustomerServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Ecommerce/Order/Customer.svc/";
            this.SF = sf;
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/batch/?provider={provider}")]
        public bool BatchDeleteCustomers(Guid[] customerIds, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/batch/?provider={provider}"), Method.POST);

            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(customerIds), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebGet(UriTemplate = "/{customerId}/?provider={provider}")]
        public ItemContext<Customer> GetCustomer(Guid customerId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/{customerId}/?provider={provider}"), Method.GET);

            request.AddUrlSegment("customerId", customerId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<ItemContext<Customer>>(request);
        }

        //[WebGet(UriTemplate = "/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<Customer> GetCustomers(string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<Customer>>(request);
        }
    }
}
