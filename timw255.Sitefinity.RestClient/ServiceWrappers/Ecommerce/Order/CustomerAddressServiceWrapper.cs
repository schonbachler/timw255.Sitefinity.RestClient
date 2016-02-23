﻿using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using timw255.Sitefinity.RestClient.Model;

namespace timw255.Sitefinity.RestClient.ServiceWrappers.Ecommerce.Order
{
    public class CustomerAddressServiceWrapper : ServiceWrapper
    {
        public CustomerAddressServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Ecommerce/Order/CustomerAddress.svc/";
            this.SF = sf;
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/batchdelete/?provider={provider}")]
        public bool BatchDeleteCustomerAddresses(Guid[] customerAddressIds, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/batchdelete/?provider={provider}"), Method.POST);

            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(customerAddressIds), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "DELETE", UriTemplate = "/{customerAddressId}/?provider={provider}")]
        public bool DeleteCustomerAddress(Guid customerAddressId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/{customerAddressId}/?provider={provider}"), Method.DELETE);

            request.AddUrlSegment("customerAddressId", customerAddressId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<bool>(request);
        }

        //[WebGet(UriTemplate = "/{customerAddressId}/?provider={providerName}")]
        public ItemContext<CustomerAddress> GetCustomerAddress(Guid customerAddressId, string providerName)
        {
            var request = new RestRequest(this.GetServiceUrl("/{customerAddressId}/?provider={providerName}"), Method.GET);

            request.AddUrlSegment("customerAddressId", customerAddressId.ToString());
            request.AddUrlSegment("providerName", providerName);

            return ExecuteRequest<ItemContext<CustomerAddress>>(request);
        }

        //[WebGet(UriTemplate = "/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<CustomerAddress> GetCustomerAddresses(string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<CustomerAddress>>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/{customerAddressId}/?provider={providerName}")]
        public ItemContext<CustomerAddress> SaveCustomerAddress(ItemContext<CustomerAddress> customerAddressContext, Guid customerAddressId, string providerName)
        {
            var request = new RestRequest(this.GetServiceUrl("/{customerAddressId}/?provider={providerName}"), Method.PUT);

            request.AddUrlSegment("customerAddressId", customerAddressId.ToString());
            request.AddUrlSegment("providerName", providerName);

            request.AddParameter("application/json", SerializeObject(customerAddressContext), ParameterType.RequestBody);

            return ExecuteRequest<ItemContext<CustomerAddress>>(request);
        }
    }
}
