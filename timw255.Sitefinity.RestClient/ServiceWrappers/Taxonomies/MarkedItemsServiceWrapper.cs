﻿using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using timw255.Sitefinity.RestClient.Model;

namespace timw255.Sitefinity.RestClient.ServiceWrappers.Taxonomies
{
    public class MarkedItemsServiceWrapper : ServiceWrapper
    {
        public MarkedItemsServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Taxonomies/MarkedItems.svc/";
            this.SF = sf;
        }

        //[WebInvoke(Method = "GET", UriTemplate = "/items/{taxonId}/?itemType={itemType}&provider={provider}&itemProvider={itemProvider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<WcfMarketContentItem> GetItems(Guid taxonId, string itemType, string provider, string itemProvider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/items/{taxonId}/?itemType={itemType}&provider={provider}&itemProvider={itemProvider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);
            
            request.AddUrlSegment("taxonId", taxonId.ToString());
            request.AddUrlSegment("itemType", itemType);
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("itemProvider", itemProvider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<WcfMarketContentItem>>(request);
        }

        //[WebInvoke(Method = "GET", UriTemplate = "/{taxonId}/?provider={provider}")]
        public CollectionContext<WcfTaxonStatistic> GetTaxonStatistics(Guid taxonId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/{taxonId}/?provider={provider}"), Method.GET);

            request.AddUrlSegment("taxonId", taxonId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<CollectionContext<WcfTaxonStatistic>>(request);
        }

        //[WebInvoke(Method = "DELETE", UriTemplate = "/items/{taxonId}/{itemIDs}/?itemType={itemType}&provider={provider}&itemProvider={itemProvider}")]
        public bool RemoveItemFromTaxon(Guid taxonId, string itemType, string itemIDs, string provider, string itemProvider)
        {
            var request = new RestRequest(this.GetServiceUrl("/items/{taxonId}/{itemIDs}/?itemType={itemType}&provider={provider}&itemProvider={itemProvider}"), Method.DELETE);

            request.AddUrlSegment("taxonId", taxonId.ToString());
            request.AddUrlSegment("itemIDs", itemIDs);
            request.AddUrlSegment("itemType", itemType);
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("itemProvider", itemProvider);

            return ExecuteRequest<bool>(request);
        }
    }
}
