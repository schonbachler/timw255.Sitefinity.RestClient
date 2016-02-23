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
    public class CampaignServiceWrapper : ServiceWrapper
    {
        public CampaignServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Newsletters/Campaign.svc/";
            this.SF = sf;
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/batchdelete/?provider={provider}")]
        public bool BatchDeleteCampaigns(Guid[] campaignIds, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/batchdelete/?provider={provider}"), Method.POST);

            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(campaignIds), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/issue/batchdelete/?provider={provider}")]
        public bool BatchDeleteIssues(Guid[] issueIds, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/issue/batchdelete/?provider={provider}"), Method.POST);

            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(issueIds), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "DELETE", UriTemplate = "/{campaignId}/?provider={provider}")]
        public bool DeleteCampaign(Guid campaignId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/{campaignId}/?provider={provider}"), Method.DELETE);

            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(campaignId), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "DELETE", UriTemplate = "/issue/{issueId}/?provider={provider}")]
        public bool DeleteIssue(Guid issueId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/issue/{issueId}/?provider={provider}"), Method.DELETE);

            request.AddUrlSegment("issueId", issueId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<bool>(request);
        }

        //[WebGet(UriTemplate = "/{campaignId}/?provider={provider}")]
        public CampaignViewModel GetCampaign(Guid campaignId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/{campaignId}/?provider={provider}"), Method.GET);

            request.AddUrlSegment("campaignId", campaignId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<CampaignViewModel>(request);
        }

        //[WebGet(UriTemplate = "/issues/{rootCampaignId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<IssueGridViewModel> GetCampaignIssues(Guid rootCampaignId, string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/issues/{rootCampaignId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("rootCampaignId", rootCampaignId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<IssueGridViewModel>>(request);
        }

        //[WebGet(UriTemplate = "/obsolete/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<CampaignViewModel> GetCampaigns(string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/obsolete/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<CampaignViewModel>>(request);
        }

        //[WebGet(UriTemplate = "/issue/{issueId}/?provider={provider}")]
        public IssueViewModel GetIssue(Guid issueId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/issue/{issueId}/?provider={provider}"), Method.GET);

            request.AddUrlSegment("issueId", issueId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<IssueViewModel>(request);
        }

        //[WebGet(UriTemplate = "/issues/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<IssueGridViewModel> GetIssues(string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/issues/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<IssueGridViewModel>>(request);
        }

        //[WebGet(UriTemplate = "/mergetags/{mailingListId}/?provider={provider}")]
        public CollectionContext<MergeTagViewModel> GetMergeTags(Guid mailingListId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/mergetags/{mailingListId}/?provider={provider}"), Method.GET);

            request.AddUrlSegment("mailingListId", mailingListId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<CollectionContext<MergeTagViewModel>>(request);
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/rawmessage/")]
        public MessageBodyViewModel GetRawMessage(MessageBodyViewModel messageBody)
        {
            var request = new RestRequest(this.GetServiceUrl("/rawmessage/"), Method.POST);

            request.AddParameter("application/json", SerializeObject(messageBody), ParameterType.RequestBody);

            return ExecuteRequest<MessageBodyViewModel>(request);
        }

        //[WebGet(UriTemplate = "/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<CampaignGridViewModel> GetRootCampaigns(string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<CampaignGridViewModel>>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/{campaignId}/?provider={provider}")]
        public CampaignViewModel SaveCampaign(Guid campaignId, CampaignViewModel campaign, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/{campaignId}/?provider={provider}"), Method.PUT);

            request.AddUrlSegment("campaignId", campaignId.ToString());
            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(campaign), ParameterType.RequestBody);

            return ExecuteRequest<CampaignViewModel>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/issue/{issueId}/?provider={provider}")]
        public IssueViewModel SaveIssue(Guid issueId, IssueViewModel issue, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/issue/{issueId}/?provider={provider}"), Method.PUT);

            request.AddUrlSegment("issueId", issueId.ToString());
            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(issue), ParameterType.RequestBody);

            return ExecuteRequest<IssueViewModel>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/schedule/{campaignId}/?provider={provider}")]
        public void ScheduleCampaign(Guid campaignId, DateTime deliveryDate, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/schedule/{campaignId}/?provider={provider}"), Method.PUT);

            request.AddUrlSegment("campaignId", campaignId.ToString());
            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(deliveryDate), ParameterType.RequestBody);

            ExecuteRequest(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/send/?provider={provider}")]
        public void SendCampaign(Guid campaignId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/send/?provider={provider}"), Method.PUT);

            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(campaignId), ParameterType.RequestBody);

            ExecuteRequest(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/sendtest/?provider={provider}", BodyStyle = WebMessageBodyStyle.WrappedRequest)]
        public void SendTestCampaign(string provider, CampaignViewModel campaign, string[] testEmailAddresses)
        {
            var request = new RestRequest(this.GetServiceUrl("/sendtest/?provider={provider}"), Method.PUT);

            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(campaign), ParameterType.RequestBody);
            request.AddParameter("application/json", SerializeObject(testEmailAddresses), ParameterType.RequestBody);

            ExecuteRequest(request);
        }

        //[Obsolete("Use SendTestCampaign(string provider, CampaignViewModel campaign, string[] testEmailAddresses).")]
        //[WebInvoke(Method = "PUT", UriTemplate = "/sendtest/{campaignId}/?provider={provider}")]
        public void SendTestMessage(Guid campaignId, string provider, string[] testEmailAddresses)
        {
            var request = new RestRequest(this.GetServiceUrl("/sendtest/{campaignId}/?provider={provider}"), Method.PUT);

            request.AddUrlSegment("campaignId", campaignId.ToString());
            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(testEmailAddresses), ParameterType.RequestBody);

            ExecuteRequest(request);
        }
    }
}
