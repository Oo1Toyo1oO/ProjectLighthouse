#nullable enable
using System.Text;
using LBPUnion.ProjectLighthouse.Configuration;
using LBPUnion.ProjectLighthouse.Extensions;
using LBPUnion.ProjectLighthouse.Files;
using LBPUnion.ProjectLighthouse.Logging;
using LBPUnion.ProjectLighthouse.Servers.GameServer.Types.Misc;
using LBPUnion.ProjectLighthouse.Types.Logging;
using LBPUnion.ProjectLighthouse.Types.Resources;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using IOFile = System.IO.File;

// for archive.org resoruce getter 
using System.IO;
using System.Net.Http;
// ^^^
namespace LBPUnion.ProjectLighthouse.Servers.GameServer.Controllers.Resources;

[ApiController]
[Authorize]
[Produces("text/xml")]
[Route("LITTLEBIGPLANETPS3_XML")]
public class ResourcesController : ControllerBase
{

    [HttpPost("showModerated")]
    public IActionResult ShowModerated() => this.Ok(new ResourceList());

    [HttpPost("filterResources")]
    [HttpPost("showNotUploaded")]
    public async Task<IActionResult> FilterResources()
    {
        ResourceList? resourceList = await this.DeserializeBody<ResourceList>();
        if (resourceList?.Resources == null) return this.BadRequest();

        resourceList.Resources = resourceList.Resources.Where(r => !FileHelper.ResourceExists(r)).ToArray();

        return this.Ok(resourceList);
    }

    [HttpGet("r/{hash}")]
    public IActionResult GetResource(string hash)
    {
        string path = FileHelper.GetResourcePath(hash);

        string fullPath = Path.GetFullPath(path);

        // Prevent directory traversal attacks
        if (!fullPath.StartsWith(FileHelper.FullResourcePath)) return this.BadRequest();

        if (FileHelper.ResourceExists(hash)) return this.File(IOFile.OpenRead(path), "application/octet-stream");
		
		// for archive.org resoruce getter 
        string a = hash.Substring(0, 2);
        string b = hash.Substring(2, 2);
        string c = hash.Substring(0, 1);
        string url = $"https://archive.org/download/dry23r{c}/dry{a}.zip/{a}/{b}/{hash}";

        
		using (HttpClient client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = true }))
		{
			var response = client.GetAsync(url).Result;
			if (response.IsSuccessStatusCode && response.Content.Headers.ContentType.MediaType == "application/octet-stream")
			{
				var stream = response.Content.ReadAsStreamAsync().Result;
				return this.File(stream, "application/octet-stream");
			}
		}

        // ^^^
		return this.NotFound();
    }

    [HttpPost("upload/{hash}/unattributed")]
    [HttpPost("upload/{hash}")]
    public async Task<IActionResult> UploadResource(string hash)
    {
        string assetsDirectory = FileHelper.ResourcePath;
        string path = FileHelper.GetResourcePath(hash);
        string fullPath = Path.GetFullPath(path);

        FileHelper.EnsureDirectoryCreated(assetsDirectory);

        // Deny request if in read-only mode
        if (ServerConfiguration.Instance.UserGeneratedContentLimits.ReadOnlyMode) return this.BadRequest();

        // LBP treats code 409 as success and as an indicator that the file is already present
        if (FileHelper.ResourceExists(hash)) return this.Conflict();

        // Theoretically shouldn't be possible because of hash check but handle anyways
        if (!fullPath.StartsWith(FileHelper.FullResourcePath)) return this.BadRequest();

        Logger.Info($"Processing resource upload (hash: {hash})", LogArea.Resources);
        byte[] data = await this.Request.BodyReader.ReadAllAsync();
        LbpFile file = new(data);

        if (!FileHelper.IsFileSafe(file))
        {
            Logger.Warn($"File is unsafe (hash: {hash}, type: {file.FileType})", LogArea.Resources);
            if (file.FileType == LbpFileType.Unknown)
            {
                Logger.Warn($"({hash}): File header: '{Convert.ToHexString(data[..4])}', " +
                            $"ascii='{Encoding.ASCII.GetString(data[..4])}'",
                    LogArea.Resources);
            }
            return this.Conflict();
        }

        if (!FileHelper.AreDependenciesSafe(file))
        {
            Logger.Warn($"File has unsafe dependencies (hash: {hash}, type: {file.FileType}", LogArea.Resources);
            return this.Conflict();
        }

        string calculatedHash = file.Hash;
        if (calculatedHash != hash)
        {
            Logger.Warn
                ($"File hash does not match the uploaded file! (hash: {hash}, calculatedHash: {calculatedHash}, type: {file.FileType})", LogArea.Resources);
            return this.Conflict();
        }

        Logger.Success($"File is OK! (hash: {hash}, type: {file.FileType})", LogArea.Resources);
        await IOFile.WriteAllBytesAsync(path, file.Data);
        return this.Ok();
    }
}