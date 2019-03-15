import java.time.LocalTime;

import com.espertech.esper.client.EPRuntime;

public class LogTailerHTTP implements LogTailerListener {
    	
        EPRuntime cepHTTP;
        
        LogTailerHTTP(EPRuntime cep) {
        	this.cepHTTP = cep;
        }

        //String badLogin = "password incorrect!";
        //String correctLogin = "Logged on";

        public void update(String line){
        	
        
            String[] splittedLine = line.split("\\s+");

 
            String ipAddr = splittedLine[0];


            String requestType = line.split("\"")[1].split("\\s+")[0];
            
            String requestDoc = line.split("\"")[1].split("\\s+")[1];


            //DEBUG Ausgabe:
            //System.out.println("HTTP whole line: " + line);
            
            infoHelper helper = infoHelper.getInstance();
            
            String timeStamp = helper.getTimeStamp();
            long counter = helper.getIncrementedCounter();
            
            //DEBUG Ausgabe:
            //System.out.println("TimeStamp: " + timeStamp);
            //System.out.println("Counter: " + counter);


            cepHTTP.sendEvent(new EPLhttpEventConfig(requestType, ipAddr, requestDoc, timeStamp, counter));

        }

        public void handleRemovedFile(){
            System.out.println("File was removed! - Handler nicht implementiert");
        }

        public void handleException(Exception exception){
            System.out.println("Some exception happend");
            System.out.println(exception);
        }

        public void fileNotFound(){
            System.out.println("Error: File not Found!!");
        }
    }