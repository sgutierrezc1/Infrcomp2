package caso2;

import uniandes.gload.core.Task;
import uniandes.gload.examples.clientserver.Client;

public class ClientServerTask extends Task{

	@Override
	public void fail() {
		// TODO Auto-generated method stub
		System.out.println(Task.MENSAJE_FAIL);
	}

	@Override
	public void success() {
		// TODO Auto-generated method stub
		System.out.println(Task.OK_MESSAGE);
	}

	@Override
	public void execute() {
		// TODO Auto-generated method stub
		try {
			Cliente cliente= new Cliente();
			cliente.enviarPosicion("41 24.2028, 2 10.4418");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			fail();
		}
	}

}
