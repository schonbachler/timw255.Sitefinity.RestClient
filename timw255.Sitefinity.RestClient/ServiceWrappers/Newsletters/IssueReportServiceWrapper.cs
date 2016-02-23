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
    public class IssueReportServiceWrapper : ServiceWrapper
    {
        public IssueReportServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Newsletters/IssueReport.svc/";
            this.SF = sf;
        }

        //[WebGet(UriTemplate = "/clicks/{issueId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<SubscriberIssueClickViewModel> GetIssueClicks(Guid issueId, string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/clicks/{issueId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("issueId", issueId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<SubscriberIssueClickViewModel>>(request);
        }

        //[WebGet(UriTemplate = "/clicksbyhour/{issueId}/?provider={provider}")]
        public IEnumerable<KeyValuePair<string, int>> GetIssueClicksByHour(Guid issueId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/clicksbyhour/{issueId}/?provider={provider}"), Method.GET);

            request.AddUrlSegment("issueId", issueId.ToString());
            request.AddUrlSegment("provider", provider);
            
            return ExecuteRequest<IEnumerable<KeyValuePair<string, int>>>(request);
        }

        //[Obsolete("Use Campaign.svc/issues/ instead.")]
        //[WebGet(UriTemplate = "/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public IEnumerable<IssueReportViewModel> GetIssueReports(string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<IEnumerable<IssueReportViewModel>>(request);
        }

        //[WebGet(UriTemplate = "/subscriberclicks/{issueId}/?subscriberId={subscriberId}&provider={provider}")]
        public IEnumerable<SubscriberIssueClickViewModel> GetIssueSubscriberClicks(Guid issueId, Guid subscriberId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/subscriberclicks/{issueId}/?subscriberId={subscriberId}&provider={provider}"), Method.GET);

            request.AddUrlSegment("issueId", issueId.ToString());
            request.AddUrlSegment("subscriberId", subscriberId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<IEnumerable<SubscriberIssueClickViewModel>>(request);
        }

        //[WebGet(UriTemplate = "/subscribers/{issueId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}&byClickedLink={byClickedLink}")]
        public CollectionContext<IssueSubscriberViewModel> GetIssueSubscribers(Guid issueId, string provider, string sortExpression, int skip, int take, string filter, string byClickedLink)
        {
            var request = new RestRequest(this.GetServiceUrl("/subscribers/{issueId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}&byClickedLink={byClickedLink}"), Method.GET);

            request.AddUrlSegment("issueId", issueId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);
            request.AddUrlSegment("byClickedLink", byClickedLink);

            return ExecuteRequest<CollectionContext<IssueSubscriberViewModel>>(request);
        }

        //[WebGet(UriTemplate = "/totallinkclicks/{issueId}/?search={search}&provider={provider}")]
        public IEnumerable<KeyValuePair<string, int>> GetIssueTotalLinkClicks(Guid issueId, string search, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/totallinkclicks/{issueId}/?search={search}&provider={provider}"), Method.GET);

            request.AddUrlSegment("issueId", issueId.ToString());
            request.AddUrlSegment("search", search);
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<IEnumerable<KeyValuePair<string, int>>>(request);
        }

        //[WebGet(UriTemplate = "/uniqueclicks/{issueId}/?provider={provider}")]
        public IEnumerable<ClickStatViewModel> GetIssueUniqueClicks(Guid issueId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/uniqueclicks/{issueId}/?provider={provider}"), Method.GET);

            request.AddUrlSegment("issueId", issueId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<IEnumerable<ClickStatViewModel>>(request);
        }
    }
}
