using System;
using System.Text.Json;

using Microsoft.Windows.EventTracing.Events;

using static NetBlameCustomDataSource.Util; // Assert


namespace NetBlameCustomDataSource.Chromium
{
	class ResolvedDNS
	{
		public string Domain; // "star-mini.c1q0r.facebook.com"
		public string Alias;  // "www.facebook.com" or null
		public string[] rgAddress; // never null, no missing or white-space elements, no port numbers
	}

	static class DNSInfo
	{
		/*
			Parse the JSON string from the 'params' field where: 'source_type' == 'HOST_RESOLVER_IMPL_JOB'

			Simplified Input:
			{
			"results":
			 [
			  {
			  "domain_name":"ax-0001.ax-msedge.net",
			  "endpoints":
			   [
			    { "address":"150.171.27.10" },
			    { "address":"150.171.28.10" }
			   ],
			  "type":"data"
			  },
			  {
			  "alias_target":"c-bing-com.ax-0001.ax-msedge.net",
			  "domain_name":"c.bing.com",
			  "type":"alias"
			  },
			  {
			  "alias_target":"ax-0001.ax-msedge.net",
			  "domain_name":"c-bing-com.ax-0001.ax-msedge.net",
			  "type":"alias"
			  }
			 ],
			}

			Output:
				Domain = "ax-0001.ax-msedge.net"
				Alias =  "c.bing.com"
				rgAddress = { "150.171.27.10", "150.171.28.10" }
		*/
		static ResolvedDNS ParseHostResolveDNS(string json)
		{
			JsonDocument jd = null;
			try
			{
				jd = JsonDocument.Parse(json);
			}
			catch
			{
				jd = null;
			}

			if (jd == null)
				return null;

			using (jd)
			{
				if (!jd.RootElement.TryGetProperty("results", out JsonElement results) || results.ValueKind != JsonValueKind.Array || results.GetArrayLength() == 0)
					return null;

				bool[] rgAlias = new bool[results.GetArrayLength()];

				string[] rgEndPoints = null;

				string sDomain = null;
				int iRes = -1;
				foreach (var res in results.EnumerateArray())
				{
					++iRes;

					if (!res.TryGetProperty("type", out JsonElement type) || type.ValueKind != JsonValueKind.String)
						continue;

					switch (type.GetString())
					{
					case "data":
						break;

					case "alias":
						rgAlias[iRes] = true;
						continue;

				// 	case "metadata":
				// 	case "error":
					default:
						continue;
					}

					// Only one "data" element!
					AssertImportant(sDomain == null);

					if (!res.TryGetProperty("domain_name", out JsonElement domain_name) || type.ValueKind != JsonValueKind.String)
						continue;

					sDomain = domain_name.GetString();

					if (string.IsNullOrWhiteSpace(sDomain))
					{
						sDomain = null;
						continue;
					}

					if (!res.TryGetProperty("endpoints", out JsonElement endpoints) || endpoints.ValueKind != JsonValueKind.Array || endpoints.GetArrayLength() == 0)
						continue;

					int iEP = 0;
					rgEndPoints = new string[endpoints.GetArrayLength()];
					foreach (var endpoint in endpoints.EnumerateArray())
					{
						if (!endpoint.TryGetProperty("address", out JsonElement address) || address.ValueKind != JsonValueKind.String)
							continue;

						if (string.IsNullOrWhiteSpace(address.GetString()))
							continue;

						rgEndPoints[iEP++] = address.GetString();
					}

					// Continue the loop only to populate: rgAlias[iRes]
				} // foreach res

				if (sDomain == null)
					return null;

				if (rgEndPoints == null)
					return null;

				// Find and trim any trailing null strings. (None have ever been observed.)

				int iEmpty = Array.FindIndex(rgEndPoints, s => s == null);

				if (iEmpty == 0)
					return null;

				if (iEmpty > 0)
					rgEndPoints = rgEndPoints[..iEmpty];

				// Now scan through the "alias" elements, matching alias to domain, and ultimately arriving at a final domain. (Truncated N^2 for small N)

				string target = sDomain;
				bool fAdvance;
				do
				{
					fAdvance = false;
					iRes = -1;
					foreach (var res in results.EnumerateArray())
					{
						if (!rgAlias[++iRes]) continue;

						if (!res.TryGetProperty("alias_target", out JsonElement alias_target) || alias_target.ValueKind != JsonValueKind.String)
							continue;

						if (alias_target.GetString() != target) continue;

						rgAlias[iRes] = false;

						if (!res.TryGetProperty("domain_name", out JsonElement domain_name) || domain_name.ValueKind != JsonValueKind.String)
							continue;

						target = domain_name.GetString();
						fAdvance = true;
					}
				} while (fAdvance);

				if (target == sDomain)
					target = null;

				return new ResolvedDNS
				{
					Domain = sDomain,
					Alias = target,
					rgAddress = rgEndPoints
				};
			} // using (jd)
		} // ParseHostResolveDNS


		public static Guid[] rgGuid =
		{
			new Guid("{3A5F2396-5C8F-4F1F-9B67-6CCA6C990E61}"), // Microsoft.MSEdgeStable
			new Guid("{BD089BAA-4E52-4794-A887-9E96868570D2}"), // Microsoft.MSEdgeBeta
			new Guid("{E16EC3D2-BB0F-4E8F-BDB8-DE0BEA82DC3D}"), // Microsoft.MSEdgeWebView2
			new Guid("{C56B8664-45C5-4E65-B3C7-A8D6BD3F2E67}"), // Microsoft.MSEdgeCanary
			new Guid("{D30B5C9F-B58F-4DC9-AFAF-134405D72107}"), // Microsoft.MSEdgeDev
			new Guid("{d2d578d9-2936-45b6-a09f-30e32715f42d}")  // CHROME
		};

		public static void Dispatch(in IGenericEvent evt, DNSClient.DNSTable dnsTable)
		{
			if (!evt.TaskName.Equals("HOST_RESOLVER_DNS_TASK_EXTRACTION_RESULTS"))
				return;

			AssertImportant(evt.GetString("source_type").Equals("HOST_RESOLVER_IMPL_JOB"));

			ResolvedDNS rdns = ParseHostResolveDNS(evt.GetString("params"));

			if (rdns != null)
				dnsTable.AddServerAndAddress(rdns.Domain, rdns.Alias, rdns.rgAddress);
		}
	} // DNSInfo
} // namespace NetBlameCustomDataSource.DNSClient