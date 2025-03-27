/*
 * Copyright 2015 - 2024 Anton Tananaev (anton@traccar.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.api.resource;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Context;
import org.traccar.api.BaseObjectResource;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.helper.LogAction;
import org.traccar.helper.model.UserUtil;
import org.traccar.model.Device;
import org.traccar.model.ManagedUser;
import org.traccar.model.Permission;
import org.traccar.model.User;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import java.util.Map;
import jakarta.ws.rs.core.GenericType;

@Path("users")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class UserResource extends BaseObjectResource<User> {

    @Inject
    private Config config;

    @Context
    private HttpServletRequest request;

    @Inject
    private Client client;

    public UserResource() {
        super(User.class);
    }

    @GET
    public Collection<User> get(
            @QueryParam("userId") long userId, @QueryParam("deviceId") long deviceId) throws StorageException {
        if (userId > 0) {
            permissionsService.checkUser(getUserId(), userId);
            return storage.getObjects(baseClass, new Request(
                    new Columns.All(),
                    new Condition.Permission(User.class, userId, ManagedUser.class).excludeGroups()));
        } else if (deviceId > 0) {
            permissionsService.checkManager(getUserId());
            var conditions = new LinkedList<Condition>();
            conditions.add(new Condition.Permission(User.class, Device.class, deviceId).excludeGroups());
            if (permissionsService.notAdmin(getUserId())) {
                conditions.add(new Condition.Permission(User.class, getUserId(), ManagedUser.class).excludeGroups());
            }
            return storage.getObjects(baseClass, new Request(new Columns.All(), Condition.merge(conditions)));
        } else if (permissionsService.notAdmin(getUserId())) {
            return storage.getObjects(baseClass, new Request(
                    new Columns.All(),
                    new Condition.Permission(User.class, getUserId(), ManagedUser.class).excludeGroups()));
        } else {
            return storage.getObjects(baseClass, new Request(new Columns.All()));
        }
    }

    @Override
    @PermitAll
    @POST
    public Response add(User entity) throws StorageException {
        User currentUser = getUserId() > 0 ? permissionsService.getUser(getUserId()) : null;
        if (currentUser == null || !currentUser.getAdministrator()) {
            permissionsService.checkUserUpdate(getUserId(), new User(), entity);
            if (currentUser != null && currentUser.getUserLimit() != 0) {
                int userLimit = currentUser.getUserLimit();
                if (userLimit > 0) {
                    int userCount = storage.getObjects(baseClass, new Request(
                            new Columns.All(),
                            new Condition.Permission(User.class, getUserId(), ManagedUser.class).excludeGroups()))
                            .size();
                    if (userCount >= userLimit) {
                        throw new SecurityException("Manager user limit reached");
                    }
                }
            } else {
                if (UserUtil.isEmpty(storage)) {
                    entity.setAdministrator(true);
                } else if (!permissionsService.getServer().getRegistration()) {
                    throw new SecurityException("Registration disabled");
                }
                if (permissionsService.getServer().getBoolean(Keys.WEB_TOTP_FORCE.getKey())
                        && entity.getTotpKey() == null) {
                    throw new SecurityException("One-time password key is required");
                }
                UserUtil.setUserDefaults(entity, config);
            }
        }

        entity.setId(storage.addObject(entity, new Request(new Columns.Exclude("id"))));
        storage.updateObject(entity, new Request(
                new Columns.Include("hashedPassword", "salt"),
                new Condition.Equals("id", entity.getId())));

        LogAction.create(getUserId(), entity);

        if (currentUser != null && currentUser.getUserLimit() != 0) {
            storage.addPermission(new Permission(User.class, getUserId(), ManagedUser.class, entity.getId()));
            LogAction.link(getUserId(), User.class, getUserId(), ManagedUser.class, entity.getId());
        }
        return Response.ok(entity).build();
    }

    @Path("{id}")
    @DELETE
    public Response remove(@PathParam("id") long id) throws Exception {
        Response response = super.remove(id);
        if (getUserId() == id) {
            request.getSession().removeAttribute(SessionResource.USER_ID_KEY);
        }
        return response;
    }

    @Path("{id}/enableBilling")
    @POST
    public Response enableBilling(@PathParam("id") long id) throws StorageException {
        try {
            // Check if current user is an administrator
            User currentUser = getUserId() > 0 ? permissionsService.getUser(getUserId()) : null;
            if (currentUser == null || !currentUser.getAdministrator()) {
                throw new SecurityException("Only administrators can enable billing");
            }

            // Get the target user
            User user = storage.getObject(User.class, new Request(
                    new Columns.All(), new Condition.Equals("id", id)));
            
            if (user == null) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }
            
            // Create the payment provider customer
            String paymentUserId = createPaymentProviderCustomer(user);
            
            // Update the user's attributes
            if (user.getAttributes() == null) {
                user.setAttributes(new HashMap<>());
            }
            user.getAttributes().put("billingEnabled", true);
            user.getAttributes().put("paymentUserId", paymentUserId);
            
            // Save the updated user
            storage.updateObject(user, new Request(
                    new Columns.Include("attributes"),
                    new Condition.Equals("id", id)));
            
            LogAction.edit(getUserId(), user);
            
            return Response.ok(user).build();
        } catch (SecurityException e) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity(e.getMessage())
                    .build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Error enabling billing: " + e.getMessage())
                    .build();
        }
    }

    private String createPaymentProviderCustomer(User user) {
        try {
            // Prepare request data
            Map<String, Object> requestData = new HashMap<>();
            requestData.put("name", user.getName());
            requestData.put("email", user.getEmail());
            
            // Get CPF/CNPJ from user attributes or use default
            String cpfCnpj = "61109652356"; // Default value
            if (user.getAttributes() != null && user.getAttributes().containsKey("cpfCnpj")) {
                cpfCnpj = user.getAttributes().get("cpfCnpj").toString();
            }
            requestData.put("cpfCnpj", cpfCnpj);
            
            // Make API request to payment provider
            String apiEndpoint = config.getString(Keys.PAYMENT_API_ENDPOINT) + "/v3/customers";
            String accessToken = config.getString(Keys.PAYMENT_ACCESS_TOKEN);
            
            // Send POST request
            jakarta.ws.rs.core.Response response = client.target(apiEndpoint)
                    .request(MediaType.APPLICATION_JSON)
                    .header("access_token", accessToken)
                    .post(Entity.json(requestData));
            
            // Check response status
            int status = response.getStatus();
            if (status != 200 && status != 201) {
                String errorBody;
                try {
                    // Try to get response as string
                    errorBody = response.readEntity(String.class);
                } catch (Exception e) {
                    errorBody = "Unable to read error response";
                }
                
                throw new RuntimeException(String.format(
                    "Payment provider API error: Status=%d, Response=%s", 
                    status, 
                    errorBody.isEmpty() ? "[empty response]" : errorBody));
            }
            
            // Get customer ID from response
            Map<String, Object> responseData = response.readEntity(new GenericType<Map<String, Object>>() {});
            if (responseData == null || !responseData.containsKey("id")) {
                throw new RuntimeException("Invalid response from payment provider: missing customer ID");
            }
            return responseData.get("id").toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create payment provider customer: " + e.getMessage(), e);
        }
    }

    @Path("totp")
    @PermitAll
    @POST
    public String generateTotpKey() throws StorageException {
        if (!permissionsService.getServer().getBoolean(Keys.WEB_TOTP_ENABLE.getKey())) {
            throw new SecurityException("One-time password is disabled");
        }
        return new GoogleAuthenticator().createCredentials().getKey();
    }

}
