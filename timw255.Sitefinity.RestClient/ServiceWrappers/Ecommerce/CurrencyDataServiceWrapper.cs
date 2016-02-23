﻿using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using timw255.Sitefinity.RestClient.Model;

namespace timw255.Sitefinity.RestClient.ServiceWrappers.Ecommerce
{
    public class CurrencyDataServiceWrapper : ServiceWrapper
    {
        public CurrencyDataServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Ecommerce/CurrencyData.svc/";
            this.SF = sf;
        }

        //[WebInvoke(Method="GET", UriTemplate="/ExchangeRates/CalcPrices/?currentPrice={currentPrice}", ResponseFormat=WebMessageFormat.Json)]
        public List<PriceKeyValue> CalculateCurrencyPrices(decimal currentPrice)
        {
            var request = new RestRequest(this.GetServiceUrl("/ExchangeRates/CalcPrices/?currentPrice={currentPrice}"), Method.GET);

            request.AddUrlSegment("currentPrice", currentPrice.ToString());

            return ExecuteRequest<List<PriceKeyValue>>(request);
        }

        //[WebInvoke(Method="GET", UriTemplate="/AllowedCurrencies/?siteId={siteId}", ResponseFormat=WebMessageFormat.Json)]
        public CurrenciesAllowedSettingsViewModel GetAllowedCurrenices(Guid siteId)
        {
            var request = new RestRequest(this.GetServiceUrl("/AllowedCurrencies/?siteId={siteId}"), Method.GET);

            request.AddUrlSegment("siteId", siteId.ToString());

            return ExecuteRequest<CurrenciesAllowedSettingsViewModel>(request);
        }

        //[WebInvoke(Method="GET", UriTemplate="/Currencies/?filter={filter}", ResponseFormat=WebMessageFormat.Json)]
        public CollectionContext<CurrencyViewModel> GetCurrencyInfo(string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/Currencies/?filter={filter}"), Method.GET);

            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<CurrencyViewModel>>(request);
        }

        //[WebInvoke(Method="GET", UriTemplate="/ExchangeRates/?serviceId={serviceId}&requestedCurrencies={requestedCurrencies}&defaultCurrency={defaultCurrency}&siteId={siteId}", ResponseFormat=WebMessageFormat.Json)]
        public ExchangeRateResponseViewModel GetExchangeRates(Guid serviceId, string requestedCurrencies, string defaultCurrency, Guid siteId)
        {
            var request = new RestRequest(this.GetServiceUrl("/ExchangeRates/?serviceId={serviceId}&requestedCurrencies={requestedCurrencies}&defaultCurrency={defaultCurrency}&siteId={siteId}"), Method.GET);

            request.AddUrlSegment("serviceId", serviceId.ToString());
            request.AddUrlSegment("requestedCurrencies", requestedCurrencies);
            request.AddUrlSegment("defaultCurrency", defaultCurrency);
            request.AddUrlSegment("siteId", siteId.ToString());

            return ExecuteRequest<ExchangeRateResponseViewModel>(request);
        }

        //[WebInvoke(Method="PUT", UriTemplate="allowedcurrencies/{key}/?siteId={siteId}", ResponseFormat=WebMessageFormat.Json)]
        public void SaveCurrenciesBasicSettings(ItemContext<CurrenciesAllowedSettingsViewModel> allowedCurrenciesSettings, string key, Guid siteId)
        {
            var request = new RestRequest(this.GetServiceUrl("allowedcurrencies/{key}/?siteId={siteId}"), Method.PUT);

            request.AddUrlSegment("key", key);
            request.AddUrlSegment("siteId", siteId.ToString());

            request.AddParameter("application/json", SerializeObject(allowedCurrenciesSettings), ParameterType.RequestBody);

            ExecuteRequest(request);
        }
    }
}
