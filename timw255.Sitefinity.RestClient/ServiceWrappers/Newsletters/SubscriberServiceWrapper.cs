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
    public class SubscriberServiceWrapper : ServiceWrapper
    {
        public SubscriberServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Newsletters/Subscriber.svc/";
            this.SF = sf;
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/add/{mailingListId}/?provider={provider}")]
        public bool AddSubscribers(Guid mailingListId, Guid[] subscriberIds, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/add/{mailingListId}/?provider={provider}"), Method.POST);

            request.AddUrlSegment("mailingListId", mailingListId.ToString());
            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(subscriberIds), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/batchdelete/?provider={provider}")]
        public bool BatchDeleteSubscribers(Guid[] subscriberIds, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/batchdelete/?provider={provider}"), Method.POST);

            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(subscriberIds), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "DELETE", UriTemplate = "/{subscriberId}/?provider={provider}")]
        public bool DeleteSubscriber(Guid subscriberId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/{subscriberId}/?provider={provider}"), Method.DELETE);

            request.AddUrlSegment("subscriberId", subscriberId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<bool>(request);
        }

        //[WebGet(UriTemplate = "/mailingList/{mailingListId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<SubscriberViewModel> GetMailingListSubscribers(Guid mailingListId, string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/mailingList/{mailingListId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("mailingListId", mailingListId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<SubscriberViewModel>>(request);
        }

        //[WebGet(UriTemplate = "/{subscriberId}/?provider={provider}")]
        public SubscriberViewModel GetSubscriber(Guid subscriberId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/{subscriberId}/?provider={provider}"), Method.GET);

            request.AddUrlSegment("subscriberId", subscriberId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<SubscriberViewModel>(request);
        }

        //[WebGet(UriTemplate = "/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<SubscriberViewModel> GetSubscribers(string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<SubscriberViewModel>>(request);
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/remove/{mailingListId}/?provider={provider}")]
        public bool RemoveSubscribers(Guid mailingListId, Guid[] subscriberIds, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/remove/{mailingListId}/?provider={provider}"), Method.POST);

            request.AddUrlSegment("mailingListId", mailingListId.ToString());
            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(subscriberIds), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/{subscriberId}/?provider={provider}")]
        public SubscriberViewModel SaveSubscriber(Guid subscriberId, SubscriberViewModel subscriber, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/{subscriberId}/?provider={provider}"), Method.PUT);

            request.AddUrlSegment("subscriberId", subscriberId.ToString());
            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(subscriber), ParameterType.RequestBody);

            return ExecuteRequest<SubscriberViewModel>(request);
        }
    }
}
