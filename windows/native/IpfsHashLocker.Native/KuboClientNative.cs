using System.Net.Http.Headers;
using System.Text.Json;

namespace IpfsHashLocker.Native;

public class KuboClientNative
{
    private readonly HttpClient _httpClient;
    public string ApiUrl { get; }

    public KuboClientNative(string apiUrl = "http://127.0.0.1:5001")
    {
        ApiUrl = apiUrl.TrimEnd('/');
        _httpClient = new HttpClient { BaseAddress = new Uri(ApiUrl), Timeout = TimeSpan.FromSeconds(30) };
    }

    public async Task<string?> GetNodeIdAsync()
    {
        try
        {
            var response = await _httpClient.PostAsync("/api/v0/id", null);
            if (!response.IsSuccessStatusCode) return null;
            var json = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.GetProperty("ID").GetString();
        }
        catch
        {
            return null;
        }
    }

    public async Task<string> AddFileAsync(string filePath, bool pin = true)
    {
        using var content = new MultipartFormDataContent();
        var fileBytes = await File.ReadAllBytesAsync(filePath);
        var fileContent = new ByteArrayContent(fileBytes);
        fileContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/octet-stream");
        content.Add(fileContent, "file", Path.GetFileName(filePath));

        var pinParam = pin ? "true" : "false";
        var response = await _httpClient.PostAsync($"/api/v0/add?pin={pinParam}&quieter=true", content);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("Hash").GetString()!;
    }

    public async Task<byte[]> CatAsync(string cid)
    {
        var response = await _httpClient.PostAsync($"/api/v0/cat?arg={cid}", null);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync();
    }

    public async Task<bool> PinAddAsync(string cid)
    {
        var response = await _httpClient.PostAsync($"/api/v0/pin/add?arg={cid}", null);
        return response.IsSuccessStatusCode;
    }
}
