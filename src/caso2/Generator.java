package caso2;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;
import uniandes.gload.examples.clientserver.generator.ClientServerTask;

public class Generator {

	//atributos
	/**
	 * Load generator service
	 */
	private LoadGenerator generator;
		
	//constructor
	/**
	 * Constructs a new generator
	 */
	public Generator() {
		
		Task work= createTask();
		int nTasks= 80;
		int gapBetweenTasks= 1000;
		generator= new LoadGenerator("Client - Server Load Test", nTasks, work, gapBetweenTasks);
		generator.generate();
	}
	
	/**
	 * Constructs a Task
	 * @return client server
	 */
	private Task createTask() {
		return new ClientServerTask();
	}
	
}
