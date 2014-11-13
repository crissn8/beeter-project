package edu.upc.eetac.dsa.smachado.beeter.api;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;

import javax.sql.DataSource;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.GET;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.ServerErrorException;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.EntityTag;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import edu.upc.eetac.dsa.smachado.beeter.api.model.Sting;
import edu.upc.eetac.dsa.smachado.beeter.api.model.StingCollection;
 
@Path("/stings")
public class StingResource {//entre medio de @ no puede haber ni comentarios ni espacios
	private DataSource ds = DataSourceSPA.getInstance().getDataSource();//como CRUD necesito una referencia al DataSource

	
	 
	@Context
	private SecurityContext security;
	
	private String GET_STINGS_QUERY = "select s.*, u.name from stings s, users u where u.username=s.username and s.creation_timestamp < ifnull(?, now())  order by creation_timestamp desc limit ?";
	private String GET_STINGS_QUERY_FROM_LAST = "select s.*, u.name from stings s, users u where u.username=s.username and s.creation_timestamp > ? order by creation_timestamp desc";
	private String GET_STING_BY_ID_QUERY = "select s.*, u.name from stings s, users u where u.username=s.username and s.stingid=?";
	private String INSERT_STING_QUERY = "insert into stings (username, subject, content) value (?, ?, ?)";
	private String DELETE_STING_QUERY = "delete from stings where stingid=?";
	private String UPDATE_STING_QUERY = "update stings set subject=ifnull(?, subject), content=ifnull(?, content) where stingid=?";
	private String GET_STINGS_BY_SUBJECT_CONTENT = "SELECT s.*, u.name FROM stings s, users u WHERE u.username=s.username AND subject LIKE ? OR content LIKE ? LIMIT ? ;";
	private String GET_STINGS_BY_SUBJECT = "SELECT s.*, u.name FROM stings s, users u WHERE u.username=s.username AND subject LIKE ? LIMIT ? ;";
	private String GET_STINGS_BY_CONTENT = "SELECT s.*, u.name FROM stings s, users u WHERE u.username=s.username AND  content LIKE ? LIMIT ? ;";
	
	@GET
	@Produces(MediaType.BEETER_API_STING_COLLECTION)
	public StingCollection getStings(@QueryParam("length") int length,
			@QueryParam("before") long before, @QueryParam("after") long after) {
		StingCollection stings = new StingCollection();
	 
		Connection conn = null;
		try {
			conn = ds.getConnection();
		} catch (SQLException e) {
			throw new ServerErrorException("Could not connect to the database",
					Response.Status.SERVICE_UNAVAILABLE);
		}
	 
		PreparedStatement stmt = null;
		try {
			boolean updateFromLast = after > 0;
			stmt = updateFromLast ? conn
					.prepareStatement(GET_STINGS_QUERY_FROM_LAST) : conn
					.prepareStatement(GET_STINGS_QUERY);
			if (updateFromLast) {
				stmt.setTimestamp(1, new Timestamp(after));
			} else {
				if (before > 0)
					stmt.setTimestamp(1, new Timestamp(before));
				else
					stmt.setTimestamp(1, null);
				length = (length <= 0) ? 5 : length;
				stmt.setInt(2, length);
			}
			ResultSet rs = stmt.executeQuery();
			boolean first = true;
			long oldestTimestamp = 0;
			while (rs.next()) {
				Sting sting = new Sting();
				sting.setStingid(rs.getInt("stingid"));
				sting.setUsername(rs.getString("username"));
				sting.setAuthor(rs.getString("name"));
				sting.setSubject(rs.getString("subject"));
				oldestTimestamp = rs.getTimestamp("last_modified").getTime();
				sting.setLastModified(oldestTimestamp);
				if (first) {
					first = false;
					stings.setNewestTimestamp(sting.getLastModified());
				}
				stings.addSting(sting);
			}
			stings.setOldestTimestamp(oldestTimestamp);
		} catch (SQLException e) {
			throw new ServerErrorException(e.getMessage(),
					Response.Status.INTERNAL_SERVER_ERROR);
		} finally {
			try {
				if (stmt != null)
					stmt.close();
				conn.close();
			} catch (SQLException e) {
			}
		}
	 
		return stings;
	}

	
	 
	//@GET
	//@Path("/{stingid}")
	//@Produces(MediaType.BEETER_API_STING)
	private Sting getStingFromDatabase( String stingid) {
		Sting sting = new Sting();
	 
		Connection conn = null;
		try {
			conn = ds.getConnection();
		} catch (SQLException e) {
			throw new ServerErrorException("Could not connect to the database",
					Response.Status.SERVICE_UNAVAILABLE);

		}
	 
		PreparedStatement stmt = null;
		try {
			stmt = conn.prepareStatement(GET_STING_BY_ID_QUERY);
			stmt.setInt(1, Integer.valueOf(stingid));
			ResultSet rs = stmt.executeQuery();
			if (rs.next()) {
				sting.setStingid(rs.getInt("stingid"));
				sting.setUsername(rs.getString("username"));
				sting.setAuthor(rs.getString("name"));
				sting.setSubject(rs.getString("subject"));
				sting.setContent(rs.getString("content"));
				sting.setLastModified(rs.getTimestamp("last_modified")
						.getTime());
				sting.setCreationTimestamp(rs
						.getTimestamp("creation_timestamp").getTime());
			}
			else {
				throw new NotFoundException("There's no sting with stingid="
				+ stingid);
				}
		} catch (SQLException e) {
			throw new ServerErrorException(e.getMessage(),
					Response.Status.INTERNAL_SERVER_ERROR);
		} finally {
			try {
				if (stmt != null)
					stmt.close();
				conn.close();
			} catch (SQLException e) {
			}
		}
	 
		return sting;
	}
	
//método para crear un sting
	
	
	 
	@POST
	@Consumes(MediaType.BEETER_API_STING)
	@Produces(MediaType.BEETER_API_STING)
	public Sting createSting(Sting sting) {
		validateSting(sting);

		Connection conn = null;
		try {
			conn = ds.getConnection();
		} catch (SQLException e) {
			throw new ServerErrorException("Could not connect to the database",
					Response.Status.SERVICE_UNAVAILABLE);

		}
	 
		PreparedStatement stmt = null;
		try {
			stmt = conn.prepareStatement(INSERT_STING_QUERY,
					Statement.RETURN_GENERATED_KEYS); //pedir que te devuelvan las claves primarias autogeneradas
	 
			//stmt.setString(1, sting.getUsername());
			stmt.setString(1, security.getUserPrincipal().getName());
			stmt.setString(2, sting.getSubject());
			stmt.setString(3, sting.getContent());
			stmt.executeUpdate();
			ResultSet rs = stmt.getGeneratedKeys();
			if (rs.next()) {
				int stingid = rs.getInt(1);
	 
				sting = getStingFromDatabase(Integer.toString(stingid));
			} else {
				// Something has failed...
			}
		} catch (SQLException e) {
			throw new ServerErrorException(e.getMessage(),
					Response.Status.INTERNAL_SERVER_ERROR);
		} finally {
			try {
				if (stmt != null)
					stmt.close();
				conn.close();
			} catch (SQLException e) {
			}
		}
	 
		return sting;
	}
	
	private void validateSting(Sting sting) {
		if (sting.getSubject() == null)
			throw new BadRequestException("Subject can't be null.");
		if (sting.getContent() == null)
			throw new BadRequestException("Content can't be null.");
		if (sting.getSubject().length() > 100)
			throw new BadRequestException("Subject can't be greater than 100 characters.");
		if (sting.getContent().length() > 500)
			throw new BadRequestException("Content can't be greater than 500 characters.");
	}
	
	private void validateUser(String stingid) {
	    Sting sting = getStingFromDatabase(stingid);
	    String username = sting.getUsername();
		if (!security.getUserPrincipal().getName()
				.equals(username))
			throw new ForbiddenException(
					"You are not allowed to modify this sting.");
	}
	//borrar un sting
	
	
	 
	@DELETE
	@Path("/{stingid}")
	public void deleteSting(@PathParam("stingid") String stingid) {
		
		validateUser(stingid);
		
		Connection conn = null;
		try {
			conn = ds.getConnection();
		} catch (SQLException e) {
			throw new ServerErrorException("Could not connect to the database",
					Response.Status.SERVICE_UNAVAILABLE);

		}
	 
		PreparedStatement stmt = null;
		try {
			stmt = conn.prepareStatement(DELETE_STING_QUERY);
			stmt.setInt(1, Integer.valueOf(stingid));
	 
			int rows = stmt.executeUpdate();
			if (rows == 0)
				throw new NotFoundException("There's no sting with stingid="
						+ stingid);
				;// Deleting inexistent sting. si no lo borra es q no existe
		} catch (SQLException e) {
			throw new ServerErrorException(e.getMessage(),
					Response.Status.INTERNAL_SERVER_ERROR);
		} finally {
			try {
				if (stmt != null)
					stmt.close();
				conn.close();
			} catch (SQLException e) {
			}
		}
	}
	
	//actualizar un sting
	
		
	
	 
	@PUT
	@Path("/{stingid}")
	@Consumes(MediaType.BEETER_API_STING)
	@Produces(MediaType.BEETER_API_STING)
	public Sting updateSting(@PathParam("stingid") String stingid, Sting sting) {
		validateUser(stingid);
		validateUpdateSting(sting);
		Connection conn = null;
		try {
			conn = ds.getConnection();
		} catch (SQLException e) {
			throw new ServerErrorException("Could not connect to the database",
					Response.Status.SERVICE_UNAVAILABLE);

		}
	 
		PreparedStatement stmt = null;
		try {
			stmt = conn.prepareStatement(UPDATE_STING_QUERY);
			stmt.setString(1, sting.getSubject());
			stmt.setString(2, sting.getContent());
			stmt.setInt(3, Integer.valueOf(stingid));
	 
			int rows = stmt.executeUpdate();
			if (rows == 1)
				sting = getStingFromDatabase(stingid);
			else {
				throw new NotFoundException("There's no sting with stingid="
						+ stingid);
			}
	 
		} catch (SQLException e) {
			throw new ServerErrorException(e.getMessage(),
					Response.Status.INTERNAL_SERVER_ERROR);
		} finally {
			try {
				if (stmt != null)
					stmt.close();
				conn.close();
			} catch (SQLException e) {
			}
		}
	 
		return sting;
		}
	private void validateUpdateSting(Sting sting) {
		if (sting.getSubject() != null && sting.getSubject().length() > 100)
			throw new BadRequestException(
					"Subject can't be greater than 100 characters.");
		if (sting.getContent() != null && sting.getContent().length() > 500)
			throw new BadRequestException(
					"Content can't be greater than 500 characters.");
	}
	
	
	
	@GET
	@Path("/{stingid}")
	@Produces(MediaType.BEETER_API_STING)
	public Response getSting(@PathParam("stingid") String stingid,
			@Context Request request) {
		// Create CacheControl
		CacheControl cc = new CacheControl();//crear una instancia de la cache
	 
		Sting sting = getStingFromDatabase(stingid);//recuperamos el rescurso de la base de datos
	 
		// Calculate the ETag on last modified date of user resource
		EntityTag eTag = new EntityTag(Long.toString(sting.getLastModified()));//calculamos el ETag
	 
		// Verify if it matched with etag available in http request
		Response.ResponseBuilder rb = request.evaluatePreconditions(eTag);
	 
		// If ETag matches the rb will be non-null;
		// Use the rb to return the response without any further processing
		if (rb != null) {
			return rb.cacheControl(cc).tag(eTag).build();
		}
	 
		// If rb is null then either it is first time request; or resource is
		// modified
		// Get the updated representation and return with Etag attached to it
		rb = Response.ok(sting).cacheControl(cc).tag(eTag);
	 
		return rb.build();
	}
	
	@Path("/search")
	@GET 
	@Produces(MediaType.BEETER_API_STING_COLLECTION)
	public StingCollection SearchbyContentandSubject(@QueryParam("content") String content,
			@QueryParam("subject") String subject, @QueryParam("lenght") int lenght) {
		

		StingCollection stings = new StingCollection();
	 validateSearch(subject, content);
		Connection conn = null;
		try {
			conn = ds.getConnection();
		} catch (SQLException e) {
			throw new ServerErrorException("Could not connect to the database",
					Response.Status.SERVICE_UNAVAILABLE);
		}
	 
		PreparedStatement stmt = null;
		System.out.println("Buscamos el sting mirando el subject: " +  subject + " y el content:" + content + " longitud " + lenght);
		try {
			if (lenght != 0){
				
				if (subject !=null && content !=null){
					stmt = conn.prepareStatement(GET_STINGS_BY_SUBJECT_CONTENT);
					System.out.println("Buscamos el sting a partir del subject y el content");
					stmt.setString(1, subject);
					stmt.setString(2, content);
					stmt.setInt(3, lenght);
					System.out.println(stmt);
					
				}
				else if (subject !=null && content == null){
					stmt = conn.prepareStatement(GET_STINGS_BY_SUBJECT);
					System.out.println("Buscamos el sting a partir del subject");
					stmt.setString(1, subject);
					stmt.setInt(2, lenght);
					System.out.println(stmt);
				}
				else if (subject == null && content !=null){
					stmt = conn.prepareStatement(GET_STINGS_BY_CONTENT);
					System.out.println("Buscamos el sting a partir del content");
					stmt.setString(1, content);
					stmt.setInt(2, lenght);
					System.out.println(stmt);
				}
			}
			else if (lenght == 0){
				
				
				if (subject !=null && content !=null){
					stmt = conn.prepareStatement(GET_STINGS_BY_SUBJECT_CONTENT);
					System.out.println("Buscamos el sting a partir del subject y el content");
					stmt.setString(1, subject);
					stmt.setString(2, content);
					stmt.setInt(3, 5);
					System.out.println(stmt);
					
				}
				else if (subject !=null && content == null){
					stmt = conn.prepareStatement(GET_STINGS_BY_SUBJECT);
					System.out.println("Buscamos el sting a partir del subject");
					stmt.setString(1, subject);
					stmt.setInt(2, 5);
					System.out.println(stmt);
				}
				else if (subject == null && content !=null){
					stmt = conn.prepareStatement(GET_STINGS_BY_CONTENT);
					System.out.println("Buscamos el sting a partir del content");
					stmt.setString(1, content);
					stmt.setInt(2, 5);
					System.out.println(stmt);
				}
				
				
			}
			
			ResultSet rs = stmt.executeQuery();
			System.out.println(rs);
			while (rs.next()) {
				Sting sting = new Sting();
				sting.setStingid(rs.getInt("stingid"));
				sting.setUsername(rs.getString("username"));
				sting.setAuthor(rs.getString("name"));
				sting.setSubject(rs.getString("subject"));
				sting.setContent(rs.getString("content"));
				sting.setAuthor(rs.getString("author"));
				sting.setSubject(rs.getString("subject"));
				
				stings.addSting(sting);
			}
			
		} catch (SQLException e) {
			throw new ServerErrorException(e.getMessage(),
					Response.Status.INTERNAL_SERVER_ERROR);
		} finally {
			try {
				if (stmt != null)
					stmt.close();
				conn.close();
			} catch (SQLException e) {
			}
		}
	 
		return stings;
	}
	
	
private void validateSearch(String subject, String content){
	
	if (subject == null && content ==null)
		throw new BadRequestException(
				"No se han introducido los datos");
	
}





	
}