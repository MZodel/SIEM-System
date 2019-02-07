
public class infoHelper {
	  
	  private static infoHelper instance;
	  private long counter = 0;

	  private infoHelper () {}
	  // Eine Zugriffsmethode auf Klassenebene, welches dir '''einmal''' ein konkretes 
	  // Objekt erzeugt und dieses zurückliefert.
	  // Durch 'synchronized' wird sichergestellt dass diese Methode nur von einem Thread 
	  // zu einer Zeit durchlaufen wird. Der nächste Thread erhält immer eine komplett 
	  // initialisierte Instanz.
	  
	  public static synchronized infoHelper getInstance () {
		  
	    if (infoHelper.instance == null) {
	    	infoHelper.instance = new infoHelper ();
	      
	    }
	    return infoHelper.instance;
	  }
	  
	  public long getIncrementedCounter() {
		  return this.counter++;
	  }

	  
	}