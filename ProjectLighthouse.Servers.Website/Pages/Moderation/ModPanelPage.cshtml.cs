using LBPUnion.ProjectLighthouse.Database;
using LBPUnion.ProjectLighthouse.Helpers;
using LBPUnion.ProjectLighthouse.Servers.Website.Pages.Layouts;
using LBPUnion.ProjectLighthouse.Servers.Website.Types;
using LBPUnion.ProjectLighthouse.Types.Entities.Profile;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LBPUnion.ProjectLighthouse.Servers.Website.Pages.Moderation;

public class ModPanelPage : BaseLayout
{
    public ModPanelPage(DatabaseContext database) : base(database)
    {}

    public List<AdminPanelStatistic> Statistics = new();
    
	public List<UserEntity> PlayersOnline = new();
	
    public async Task<IActionResult> OnGet()
    {
		
        UserEntity? user = this.Database.UserFromWebRequest(this.Request);
        if (user == null) return this.Redirect("~/login");
        if (!user.IsModerator) return this.NotFound();


        List<int> userIds = await this.Database.LastContacts.Where(l => TimeHelper.Timestamp - l.Timestamp < 300)
            .Select(l => l.UserId)
            .ToListAsync();
		this.PlayersOnline = await this.Database.Users.Where(u => userIds.Contains(u.UserId)).ToListAsync();
		
        this.Statistics.Add(new AdminPanelStatistic(
            statisticNamePlural: "Reports",
            count: await StatisticsHelper.ReportCount(this.Database), 
            viewAllEndpoint: "/moderation/reports/0")
        );
        
        this.Statistics.Add(new AdminPanelStatistic(
            statisticNamePlural: "Cases",
            count: await StatisticsHelper.DismissedCaseCount(this.Database), 
            viewAllEndpoint: "/moderation/cases/0",
            secondStatistic: await StatisticsHelper.CaseCount(this.Database))
        );

        return this.Page();
    }
}