//import LogTailer
import java.io.*;
import com.espertech.esper.client.*;



public class TailerImpl {
    public static void main(String argv[]) {
    	
    	// initialize Esper engine
		EPServiceProvider engine = EPServiceProviderManager.getDefaultProvider();

    	// configure Esper engine instance
		initCombinedEvents(engine);
        initFTPbruteForce(engine);
        initHTTPflood(engine);
        
        // get runtime
        EPRuntime epRunTime = engine.getEPRuntime();
        
        // start FTP Log listener
        String ftpFilePath = "C:/Program Files (x86)/FileZilla Server/Logs/FileZilla Server.log"; // Dateipfad zur Filezilla Logdatei
        File ftpLogFile = new File(ftpFilePath);
        LogTailer ftpTailer = new LogTailer(ftpLogFile);
        LogTailerFTP ftpListener = new LogTailerFTP(epRunTime);
        ftpTailer.addListener(ftpListener);
        //new Thread(ftpTailer).start();

        // start HTTP Log listener
        String httpFilePath = "C:/Apache24/logs/access.log"; // Dateipfad zur HTTP Logdatei
        File httpLogFile = new File(httpFilePath);
        LogTailer httpTailer = new LogTailer(httpLogFile);
        LogTailerHTTP httpListener = new LogTailerHTTP(epRunTime);
        httpTailer.addListener(httpListener);
        new Thread(httpTailer).start();
    }
    
    // initialize Esper FTP Brute Force events

    static void initFTPbruteForce(EPServiceProvider engine) {
    	
    	//Configuration cepConfig = new Configuration();
		//cepConfig.addEventType("Success", successAttempt.class.getName());
        //cepConfig.addEventType("Failed", failedAttempt.class.getName());
        
		//EPServiceProvider engine = EPServiceProviderManager.getProvider("CEP",cepConfig);
		
		//EPServiceProvider engine = EPServiceProviderManager.getDefaultProvider();

		engine.getEPAdministrator().getConfiguration().addEventType("Success", successAttempt.class.getName());
		engine.getEPAdministrator().getConfiguration().addEventType("Failed", failedAttempt.class.getName());

		
		
		//EPRuntime cepRT = engine.getEPRuntime();
		
		
		String epl = "create schema suspicious (source string, fails long)";
		EPAdministrator cepAdm = engine.getEPAdministrator();engine.getEPAdministrator().createEPL(epl);
		epl = "create schema failedBySource as (source string, fails long)";
        engine.getEPAdministrator().createEPL(epl);
        epl = "create schema failedByUser as (user string, fails long)";
        engine.getEPAdministrator().createEPL(epl);
        epl = "create schema successBySource as (source string, success long)";
        engine.getEPAdministrator().createEPL(epl);
        epl = "create schema successAndFailsBySource as (source string, fails long, success long)";
        engine.getEPAdministrator().createEPL(epl);
        epl = "create schema suspiciousSources as (source string, failrate double)";
        engine.getEPAdministrator().createEPL(epl);
        epl = "create schema attack as (source string)";
        engine.getEPAdministrator().createEPL(epl);
        
        //Collect fails in window
        cepAdm.createEPL("create window failWindow#length(1000000) as Failed");
        //Collect success in window
        cepAdm.createEPL("create window successWindow#length(1000000) as Success");
        
        //fails>19 partitioned by source
        cepAdm.createEPL("create window fbs#lastevent as failedBySource");
        //success partitioned by source which failed>19 times
        cepAdm.createEPL("create window sbs#lastevent as successBySource");
        //fails>19 partitioned by user
        cepAdm.createEPL("create window fbu#lastevent as failedByUser");
        //collect source and number of attempts which failed to login with specific user
        cepAdm.createEPL("create window fbus#length(1000000) as failedBySource");
        //collect number of successful attempts which failed to login with specific user
        cepAdm.createEPL("create window safbus#length(1000000) as successAndFailsBySource");
        
        //calculate rate of failure and send as event for source with more than 19 fails
        cepAdm.createEPL("create window suspSources#lastevent as suspiciousSources");
        //calculate rate of failure and send as event for user with more than 19 fails
        cepAdm.createEPL("create window suspSources2#length(1000000) as suspiciousSources");
        //in case of rate of failure is >= 0.95 classify as attack
        cepAdm.createEPL("create window att#lastevent as attack");
        cepAdm.createEPL("create window attu#length(1000000) as attack");
        
        cepAdm.createEPL("insert into failWindow select source, user from Failed").addListener(new inputListener());
        
        cepAdm.createEPL("insert into successWindow select source, user from Success").addListener(new inputListener());
        
        cepAdm.createEPL("insert into fbs select source, Count(*) as fails from failWindow group by source having Count(*)>19").addListener(new suspListener());
        cepAdm.createEPL("insert into fbu select user, Count(*) as fails from failWindow group by user having Count(*)>19").addListener(new suspUserListener());
        cepAdm.createEPL("on fbs insert into sbs select (select source from fbs), Count(*) as success from successWindow where successWindow.source=(select source from fbs) ");
        cepAdm.createEPL("on fbu insert into fbus select source, Count(*) as fails from failWindow  where failWindow.user =(select user from fbu) group by source");
        cepAdm.createEPL("insert into safbus select fbus.source as source, fbus.fails as fails, (select count(*) from successWindow where successWindow.source=fbus.source) as success from fbus").addListener(new inputListener());
        cepAdm.createEPL("select count(*) from fbus").addListener(new inputListener());
        
        cepAdm.createEPL("on sbs insert into suspSources select fbs.source as source, (fbs.fails/(fbs.fails+(select success from sbs))) as failrate from fbs").addListener(new rofListener());
        cepAdm.createEPL("on safbus insert into suspSources2 select safbus.source as source, safbus.fails/(safbus.fails+safbus.success) as failrate from safbus").addListener(new rofListener());
        //resets
        cepAdm.createEPL("on safbus delete from safbus");
        cepAdm.createEPL("on safbus delete from fbus");
        
        cepAdm.createEPL("on suspSources insert into att select suspSources.source as source from suspSources where suspSources.failrate>0.95").addListener(new attackListener(engine));
        cepAdm.createEPL("on suspSources2 insert into attu select suspSources2.source as source from suspSources2 where suspSources2.failrate>0.95").addListener(new attackListener(engine));
        
        //removing relevant data from window to avoid repeating alerts
        cepAdm.createEPL("on att delete from failWindow where failWindow.source =(select source from fbs)").addListener(new inputListener());
        cepAdm.createEPL("on att delete from successWindow where successWindow.source =(select source from fbs)").addListener(new inputListener());
        cepAdm.createEPL("on attu delete from successWindow where successWindow.source=(select source from fbus)").addListener(new inputListener());
        cepAdm.createEPL("on attu delete from failWindow where failWindow.source=(select attu.source from attu)").addListener(new inputListener());
        
        cepAdm.createEPL("on suspSources2 delete from suspSources2");
        cepAdm.createEPL("on att select att.source from att");
        
        //return cepRT;
    }
    
    // initialize Esper HTTP Flood events
    
	static void initHTTPflood(EPServiceProvider engine) {


		engine.getEPAdministrator().getConfiguration().addEventType(EPLhttpEventConfig.class);

		
		// Get all IPs which access the same document in a short time with another IP in a time frame
		String timeBetweenArrivalOf_ep_multipleIPSameDoc = "5 sec";
		String timeFrameOf_ep_multipleIPSameDoc = "1 min";

		String ep_multipleIPSameDoc = "insert into list_of_different_ips_accessing_same_document select a.sourceip as source1, b.sourceip as source2, a.wantedDocument as wantedDoc, a.timeStamp as time, a.counter as currentCount from pattern [every a=EPLhttpEventConfig -> b=EPLhttpEventConfig(a.sourceip != b.sourceip, a.wantedDocument = b.wantedDocument) where timer:within(" + timeBetweenArrivalOf_ep_multipleIPSameDoc + ")]#time(" + timeFrameOf_ep_multipleIPSameDoc + ")";

		EPStatement statement_ep_multipleIPSameDoc = engine.getEPAdministrator().createEPL(ep_multipleIPSameDoc);

		statement_ep_multipleIPSameDoc.addListener((newData, oldData) -> {
			for (int i = 0; i < newData.length; i++) {
				String source1 = (String) newData[i].get("source1");
				String source2 = (String) newData[i].get("source2");
				String wantedDoc = (String) newData[i].get("wantedDoc");
				String time = (String) newData[i].get("time");
				long currentCount = (long) newData[i].get("currentCount");
				
				//System.out.println(String.format("DEBUG #%d - (%.11s) - %s accessed at the same time by %s and %s", currentCount, time, wantedDoc, source1, source2));
			}
		});

		
		// Check if ep_multipleIPSameDoc happens too often for a single IP in a time frame
		int maxCountOf_ep_multipleIPSameDoc_TooOften = 10;
		String timeFrameOf_ep_multipleIPSameDoc_TooOften = "1 min";

		String ep_multipleIPSameDoc_TooOften = "select a.source1 as source1, a.source2 as source2, a.wantedDoc as wantedDoc, a.time as time, a.currentCount as currentCount from pattern [every a=list_of_different_ips_accessing_same_document]#time(" + timeFrameOf_ep_multipleIPSameDoc_TooOften + ") group by a.source1 having count(a.source1) > " + maxCountOf_ep_multipleIPSameDoc_TooOften;
		EPStatement statement_ep_multipleIPSameDoc_TooOften = engine.getEPAdministrator().createEPL(ep_multipleIPSameDoc_TooOften);

		statement_ep_multipleIPSameDoc_TooOften.addListener((newData, oldData) -> {
			for (int i = 0; i < newData.length; i++) {
				String source1 = (String) newData[i].get("source1");
				String source2 = (String) newData[i].get("source2");
				String time = (String) newData[i].get("time");
				long currentCount = (long) newData[i].get("currentCount");
				
				engine.getEPRuntime().sendEvent(new attackers(source1, time, currentCount, "httpFlood"));
				System.out.println(String.format("#%d - (%.11s) - %s and %s have accessed the same documents >" + maxCountOf_ep_multipleIPSameDoc_TooOften + " times", currentCount, time, source1, source2));
			}
		});

		
		// Get all IPs which access the same document multiple times in a row
		String timeBetweenArrivalOf_ep_singleIPSingleDoc = "5 sec";
		String timeFrameOf_ep_singleIPSingleDoc = "1 min";

		String ep_singleIPSingleDoc = "insert into list_of_same_ip_same_document select a.sourceip as source1, a.wantedDocument as wantedDoc, a.timeStamp as time, a.counter as currentCount from pattern [every a=EPLhttpEventConfig -> b=EPLhttpEventConfig(a.sourceip = b.sourceip, a.wantedDocument = b.wantedDocument) where timer:within(" + timeBetweenArrivalOf_ep_singleIPSingleDoc + ")]#time(" + timeFrameOf_ep_singleIPSingleDoc + ")";
		EPStatement statement_ep_singleIPSingleDoc = engine.getEPAdministrator().createEPL(ep_singleIPSingleDoc);

		statement_ep_singleIPSingleDoc.addListener((newData, oldData) -> {
			for (int i = 0; i < newData.length; i++) {
				String source1 = (String) newData[i].get("source1");
				String wantedDoc = (String) newData[i].get("wantedDoc");
				String time = (String) newData[i].get("time");
				long currentCount = (long) newData[i].get("currentCount");

				//System.out.println(String.format("DEBUG #%d - (%.11s) - %s accessed by %s twice in a row", currentCount, time, wantedDoc, source1));
			}
		});

		
		// Check if ep_singleIPSingleDoc happens too often for a single IP in a time frame
		int maxCountOf_ep_singleIPSingleDoc_TooOften = 30;
		String timeFrameOf_ep_singleIPSingleDoc_TooOften = "1 min";

		String ep_singleIPSingleDoc_TooOften = "select a.source1 as source1, a.wantedDoc as wantedDoc, a.time as time, a.currentCount as currentCount from pattern [every a=list_of_same_ip_same_document]#time(" + timeFrameOf_ep_singleIPSingleDoc_TooOften + ") group by a.source1 having count(a.source1) > " + maxCountOf_ep_singleIPSingleDoc_TooOften;
		EPStatement statement_ep_singleIPSingleDoc_TooOften = engine.getEPAdministrator().createEPL(ep_singleIPSingleDoc_TooOften);

		statement_ep_singleIPSingleDoc_TooOften.addListener((newData, oldData) -> {
			for (int i = 0; i < newData.length; i++) {
				String source1 = (String) newData[i].get("source1");
				String wantedDoc = (String) newData[i].get("wantedDoc");
				String time = (String) newData[i].get("time");
				long currentCount = (long) newData[i].get("currentCount");
				
				engine.getEPRuntime().sendEvent(new attackers(source1, time, currentCount, "httpFlood"));
				System.out.println(String.format("#%d - (%.11s) - %s accessed by %s >" + maxCountOf_ep_singleIPSingleDoc_TooOften + " times", currentCount, time, wantedDoc, source1));
			}
		});

		
		// Check if there are 2 or more IPs which access a single document together too often
		int maxCountOf_ep_multipleIPSingleDoc_TooOften = 20;
		String timeFrameOf_ep_multipleIPSingleDoc_TooOften = "1 min";
		
		String ep_multipleIPSingleDoc_TooOften = "select a.source1 as source1, a.source2 as source2, a.wantedDoc as wantedDoc, a.time as time, a.currentCount as currentCount from pattern [every a=list_of_different_ips_accessing_same_document]#time(" + timeFrameOf_ep_multipleIPSingleDoc_TooOften + ") group by a.wantedDoc, a.source1 having count(a.wantedDoc) > " + maxCountOf_ep_multipleIPSingleDoc_TooOften;
		EPStatement statement_ep_multipleIPSingleDoc_TooOften = engine.getEPAdministrator().createEPL(ep_multipleIPSingleDoc_TooOften);

		statement_ep_multipleIPSingleDoc_TooOften.addListener((newData, oldData) -> {
			for (int i = 0; i < newData.length; i++) {
				String source1 = (String) newData[i].get("source1");
				String source2 = (String) newData[i].get("source2");
				String wantedDoc = (String) newData[i].get("wantedDoc");
				String time = (String) newData[i].get("time");
				long currentCount = (long) newData[i].get("currentCount");
				
				engine.getEPRuntime().sendEvent(new attackers(source1, time, currentCount, "httpFlood"));
				System.out.println(String.format("#%d - (%.11s) - %s accessed by %s and %s >" + maxCountOf_ep_multipleIPSingleDoc_TooOften + " times", currentCount, time, wantedDoc, source1, source2));
			}
		});	


		// Check if a single IP accesses different documents too often in a time frame
		String timeBetweenArrivalOf_ep_singleIPDifDoc = "5 sec";
		String timeFrameOf_ep_singleIPDifDoc = "1 min";
		String maxCountOf_ep_singleIPDifDoc = "50";

		String ep_singleIPDifDoc = "select a.sourceip as source1, a.counter as currentCount, a.timeStamp as time from pattern [every a=EPLhttpEventConfig where timer:within(" + timeBetweenArrivalOf_ep_singleIPDifDoc + ")]#time(" + timeFrameOf_ep_singleIPDifDoc + ") group by a.sourceip having count(a.sourceip) > " + maxCountOf_ep_singleIPDifDoc;
		EPStatement statement_ep_singleIPDifDoc = engine.getEPAdministrator().createEPL(ep_singleIPDifDoc);

		statement_ep_singleIPDifDoc.addListener((newData, oldData) -> {
			for (int i = 0; i < newData.length; i++) {
				String source1 = (String) newData[i].get("source1");
				String time = (String) newData[i].get("time");
				long currentCount = (long) newData[i].get("currentCount");
				
				engine.getEPRuntime().sendEvent(new attackers(source1, time, currentCount, "httpFlood"));
				System.out.println(String.format("#%d - (%.11s) - %s accessed different documents >" + maxCountOf_ep_singleIPDifDoc + " times", currentCount, time, source1));
			}
		});


		// Check if different IPs access a single document too often in a time frame
		String timeBetweenArrivalOf_ep_difIPSingleDoc = "5 sec";
		String timeFrameOf_ep_difIPSingleDoc = "1 min";
		String maxCountOf_ep_difIPSingleDoc = "50";

		String ep_difIPSingleDoc = "select a.sourceip as source1, a.wantedDocument as wantedDoc, a.counter as currentCount, a.timeStamp as time from pattern [every a=EPLhttpEventConfig where timer:within(" + timeBetweenArrivalOf_ep_difIPSingleDoc + ")]#time(" + timeFrameOf_ep_difIPSingleDoc + ") group by a.wantedDocument having count(a.wantedDocument) > " + maxCountOf_ep_difIPSingleDoc;
		EPStatement statement_ep_difIPSingleDoc = engine.getEPAdministrator().createEPL(ep_difIPSingleDoc);

		statement_ep_difIPSingleDoc.addListener((newData, oldData) -> {
			for (int i = 0; i < newData.length; i++) {
				String wantedDoc = (String) newData[i].get("wantedDoc");
				String time = (String) newData[i].get("time");
				long currentCount = (long) newData[i].get("currentCount");
				
				System.out.println(String.format("#%d - (%.11s) - %s accessed >" + maxCountOf_ep_difIPSingleDoc + " times", currentCount, time, wantedDoc));
			}
		});
		
		
		// Check if different IPs access different documents too often in a time frame

				String timeBetweenArrivalOf_ep_difIPDifDoc = "5 sec";
				String timeFrameOf_ep_difIPDifDoc = "1 min";
				String maxCountOf_ep_difIPDifDoc = "50";
				
				String ep_difIPDifDoc = "select a.sourceip as source1, a.wantedDocument as wantedDoc, a.counter as currentCount, a.timeStamp as time from pattern [every a=EPLhttpEventConfig where timer:within(" + timeBetweenArrivalOf_ep_difIPDifDoc + ")]#time(" + timeFrameOf_ep_difIPDifDoc + ") having count(*) > " + maxCountOf_ep_difIPDifDoc;
				EPStatement statement_ep_difIPDifDoc = engine.getEPAdministrator().createEPL(ep_difIPDifDoc);
				
				statement_ep_difIPDifDoc.addListener((newData, oldData) -> {
					for (int i = 0; i < newData.length; i++) {
						String time = (String) newData[i].get("time").toString();
						long currentCount = (long) newData[i].get("currentCount");

						System.out.println(String.format("#%d - (%.11s) - General accesses >" + maxCountOf_ep_difIPDifDoc + " times", currentCount, time));
					}
				});
    }
    
    // initialize Esper for Combined events

	static void initCombinedEvents(EPServiceProvider engine) {

		engine.getEPAdministrator().getConfiguration().addEventType(attackers.class);

		// Print any IP which has been identified as an attacker
		String ep_combineAttackers = "select a.ip as ip, a.counter as currentCount, a.attackType as type1, a.timeStamp as time from pattern [every a=attackers] group by a.ip";
		EPStatement statement_ep_combineAttackers = engine.getEPAdministrator().createEPL(ep_combineAttackers);

		statement_ep_combineAttackers.addListener((newData, oldData) -> {
			for (int i = 0; i < newData.length; i++) {
				String ip = (String) newData[i].get("ip");
				String time = (String) newData[i].get("time");
				String type1 = (String) newData[i].get("type1");
				long currentCount = (long) newData[i].get("currentCount");
				
				System.out.println(String.format("#%d - (%.11s) - %s is an %s attacker", currentCount, time, ip, type1));
			}
		});
		
		
		// Check if an IP attacks with both HTTP-Flood and Bruteforce
		String timeBetweenArrivalOf_ep_compareAttackers = "1 min";
		
		String ep_compareAttackers = "select a.ip as ip, a.counter as currentCount, a.timeStamp as time, a.attackType as type1, b.attackType as type2 from pattern [every a=attackers -> b=attackers(a.ip = b.ip, a.attackType != b.attackType) where timer:within(" + timeBetweenArrivalOf_ep_compareAttackers + ")] group by a.ip";
		EPStatement statement_ep_compareAttackers = engine.getEPAdministrator().createEPL(ep_compareAttackers);

		statement_ep_compareAttackers.addListener((newData, oldData) -> {
			for (int i = 0; i < newData.length; i++) {
				String ip = (String) newData[i].get("ip");
				String time = (String) newData[i].get("time");
				long currentCount = (long) newData[i].get("currentCount");
				String type1 = (String) newData[i].get("type1");
				String type2 = (String) newData[i].get("type2");
				
				System.out.println(String.format("#%d - (%.11s) - %s is an attacker, using both %s and %s within %s", currentCount, time, ip, type1, type2, timeBetweenArrivalOf_ep_compareAttackers));
			}
		});
	}

}   

