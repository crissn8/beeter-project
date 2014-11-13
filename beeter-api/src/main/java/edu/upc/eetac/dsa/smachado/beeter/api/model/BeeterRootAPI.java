package edu.upc.eetac.dsa.smachado.beeter.api.model;

import java.util.List;

import javax.ws.rs.core.Link;
 
import org.glassfish.jersey.linking.InjectLink;
import org.glassfish.jersey.linking.InjectLink.Style;
import org.glassfish.jersey.linking.InjectLinks;
 
import edu.upc.eetac.dsa.smachado.beeter.api.BeeterRootAPIResource;
import edu.upc.eetac.dsa.smachado.beeter.api.MediaType;
import edu.upc.eetac.dsa.smachado.beeter.api.StingResource;
 //con @InjectLinks dices que es un array 
//Style.ABSOLUTE = veremos la uri entera
//1º: @path("/")
// 2º: @path("/stings")
public class BeeterRootAPI {
	@InjectLinks({
		@InjectLink(resource = BeeterRootAPIResource.class, style = Style.ABSOLUTE, rel = "self bookmark home", title = "Beeter Root API", method = "getRootAPI"),
		@InjectLink(resource = StingResource.class, style = Style.ABSOLUTE, rel = "stings", title = "Latest stings", type = MediaType.BEETER_API_STING_COLLECTION),
		@InjectLink(resource = StingResource.class, style = Style.ABSOLUTE, rel = "create-stings", title = "Latest stings", type = MediaType.BEETER_API_STING) })
	private List<Link> links; //lista de atributos
 
	public List<Link> getLinks() {
		return links;
	}
 
	public void setLinks(List<Link> links) {
		this.links = links;
	}
}