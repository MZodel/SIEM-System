import java.time.LocalTime;

import com.espertech.esper.client.EPRuntime;

public class LogTailerHTTP implements LogTailerListener {
    	
        EPRuntime cepHTTP;
        
        LogTailerHTTP(EPRuntime cep) {
        	this.cepHTTP = cep;
        }

        String badLogin = "password incorrect!";
        String correctLogin = "Logged on";
        int counter = 1;

        public void update(String line){
        	
        
            String[] splittedLine = line.split("\\s+");

            /*
            if (line.contains(badLogin)){
                String ipAddr = splittedLine [1];
                System.out.println("Bad Login Event" + "Ip address: " + ipAddr);

            }

            else if(line.contains(correctLogin)) {
                String ipAddr = splittedLine [1]; // change this
                System.out.println("Bad Login Event" + "Ip address: " + ipAddr);

            }
            */
            String ipAddr = splittedLine[0];

            //Pattern p = Pattern.compile("\"([^\"]*)\"");
            //Matcher m = p.matcher(line);

            String requestType = line.split("\"")[1].split("\\s+")[0];
            
            String requestDoc = line.split("\"")[1].split("\\s+")[1];
            
            

            System.out.println("HTTP Request IP Address: " + ipAddr);
            System.out.println("HTTP requestType: " + requestType);
            System.out.println("HTTP requestDoc: " + requestDoc);

            //System.out.println("HTTP whole line: " + line);
            
            
            
            LocalTime timeStamp = LocalTime.now();
            long counter = infoHelper.getInstance().getIncrementedCounter();
            
            System.out.println("TimeStamp: " + timeStamp);
            System.out.println("Counter: " + counter);


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