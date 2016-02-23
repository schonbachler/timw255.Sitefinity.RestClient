﻿using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using timw255.Sitefinity.RestClient.Model;

namespace timw255.Sitefinity.RestClient.ServiceWrappers.Ecommerce.Order
{
    public class OrderDownloadServiceWrapper : ServiceWrapper
    {
        public OrderDownloadServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Ecommerce/Order/OrderDownload.svc/";
            this.SF = sf;
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/batch/?provider={provider}")]
        public bool BatchDeleteOrderDownloads(Guid[] orderDownloadIds, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/batch/?provider={provider}"), Method.POST);

            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(orderDownloadIds), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "DELETE", UriTemplate = "/{orderDownloadId}/?provider={provider}")]
        public bool DeleteOrderDownload(Guid orderDownloadId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/{orderDownloadId}/?provider={provider}"), Method.DELETE);

            request.AddUrlSegment("orderDownloadId", orderDownloadId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<bool>(request);
        }

        //[WebGet(UriTemplate = "/{orderDownloadId}/?provider={provider}")]
        public ItemContext<OrderDownload> GetOrderDownload(Guid orderDownloadId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/{orderDownloadId}/?provider={provider}"), Method.GET);

            request.AddUrlSegment("orderDownloadId", orderDownloadId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<ItemContext<OrderDownload>>(request);
        }

        //[WebGet(UriTemplate = "/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<OrderDownload> GetOrderDownloads(string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<OrderDownload>>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/{orderDownloadId}/?provider={provider}")]
        public ItemContext<OrderDownload> SaveOrderDownload(Guid orderDownloadId, ItemContext<OrderDownload> orderDownload, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/{orderDownloadId}/?provider={provider}"), Method.PUT);

            request.AddUrlSegment("orderDownloadId", orderDownloadId.ToString());
            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(orderDownload), ParameterType.RequestBody);

            return ExecuteRequest<ItemContext<OrderDownload>>(request);
        }
    }
}
