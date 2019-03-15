
public class attackers {

	private String ip;
	private String timeStamp;
	private long counter;
	private String attackType;
	
	public attackers(String ip, String timeStamp, long counter, String attackType) {
		this.setIp(ip);
		this.setTimeStamp(timeStamp);
		this.setCounter(counter);
		this.setAttackType(attackType);
	}

	public String getIp() {
		return ip;
	}

	public void setIp(String ip) {
		this.ip = ip;
	}

	public String getTimeStamp() {
		return timeStamp;
	}

	public void setTimeStamp(String timeStamp) {
		this.timeStamp = timeStamp;
	}

	public long getCounter() {
		return counter;
	}

	public void setCounter(long counter) {
		this.counter = counter;
	}

	public String getAttackType() {
		return attackType;
	}

	public void setAttackType(String attackType) {
		this.attackType = attackType;
	}
}
