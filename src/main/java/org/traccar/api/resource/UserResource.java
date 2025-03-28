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
import org.traccar.model.Server;
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
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;
import jakarta.ws.rs.HeaderParam;

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
    public Response enableBilling(@PathParam("id") long id, Map<String, Object> data) throws StorageException {
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
            
            // Extract cycle from request data, default to MONTHLY
            String cycle = "MONTHLY";
            if (data != null && data.containsKey("cycle")) {
                cycle = data.get("cycle").toString();
                // Validate cycle value
                if (!isValidCycle(cycle)) {
                    return Response.status(Response.Status.BAD_REQUEST)
                            .entity("Invalid billing cycle. Valid values are: WEEKLY, BIWEEKLY, MONTHLY, BIMONTHLY, QUARTERLY, SEMIANNUALLY, YEARLY")
                            .build();
                }
            }
            
            // Get discount percentage based on cycle from server attributes
            double discountPercentage = getDiscountForCycle(cycle, permissionsService.getServer());
            
            // Extract device IDs from request data
            List<Long> deviceIds = new LinkedList<>();
            if (data != null && data.containsKey("deviceIds")) {
                if (data.get("deviceIds") instanceof List) {
                    ((List<?>) data.get("deviceIds")).forEach(deviceId -> {
                        if (deviceId instanceof Number) {
                            deviceIds.add(((Number) deviceId).longValue());
                        } else if (deviceId instanceof String) {
                            try {
                                deviceIds.add(Long.parseLong((String) deviceId));
                            } catch (NumberFormatException e) {
                                // Skip invalid IDs
                            }
                        }
                    });
                }
            }
            
            if (deviceIds.isEmpty()) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("At least one device ID must be provided")
                        .build();
            }
            
            // Verify the devices belong to the user
            List<Device> devices = new LinkedList<>();
            for (Long deviceId : deviceIds) {
                devices.addAll(storage.getObjects(Device.class, new Request(
                        new Columns.All(),
                        new Condition.And(
                                new Condition.Equals("id", deviceId),
                                new Condition.Permission(User.class, user.getId(), Device.class)))));
            }
            
            if (devices.isEmpty()) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("No valid devices found for the user")
                        .build();
            }
            
            // Create the payment provider customer with device observations
            String paymentUserId = createPaymentProviderCustomer(user, deviceIds);
            
            // Create subscription based on these devices
            String subscriptionId = createPaymentProviderSubscription(user, paymentUserId, cycle, devices, discountPercentage);
            
            // Update the user's attributes
            if (user.getAttributes() == null) {
                user.setAttributes(new HashMap<>());
            }
            user.getAttributes().put("billingEnabled", true);
            user.getAttributes().put("paymentUserId", paymentUserId);
            user.getAttributes().put("billingCycle", cycle);
            
            // Save the updated user
            storage.updateObject(user, new Request(
                    new Columns.Include("attributes"),
                    new Condition.Equals("id", id)));
            
            // Update each device with the subscription ID
            for (Device device : devices) {
                if (device.getAttributes() == null) {
                    device.setAttributes(new HashMap<>());
                }
                device.getAttributes().put("subscriptionId", subscriptionId);
                storage.updateObject(device, new Request(
                        new Columns.Include("attributes"),
                        new Condition.Equals("id", device.getId())));
            }
            
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

    private boolean isValidCycle(String cycle) {
        return cycle != null && (
                cycle.equals("WEEKLY") ||
                cycle.equals("BIWEEKLY") ||
                cycle.equals("MONTHLY") ||
                cycle.equals("BIMONTHLY") ||
                cycle.equals("QUARTERLY") ||
                cycle.equals("SEMIANNUALLY") ||
                cycle.equals("YEARLY"));
    }

    private double getDiscountForCycle(String cycle, Server server) {
        double discountPercentage = 0;
        
        if (server.getAttributes() != null) {
            switch (cycle) {
                case "BIMONTHLY":
                    if (server.getAttributes().containsKey("BIMONTHLY_DISCOUNT")) {
                        try {
                            discountPercentage = Double.parseDouble(server.getAttributes().get("BIMONTHLY_DISCOUNT").toString());
                        } catch (NumberFormatException e) {
                            // Use default of 0% if attribute value is invalid
                        }
                    }
                    break;
                case "QUARTERLY":
                    if (server.getAttributes().containsKey("QUARTERLY_DISCOUNT")) {
                        try {
                            discountPercentage = Double.parseDouble(server.getAttributes().get("QUARTERLY_DISCOUNT").toString());
                        } catch (NumberFormatException e) {
                            // Use default of 0% if attribute value is invalid
                        }
                    }
                    break;
                case "SEMIANNUALLY":
                    if (server.getAttributes().containsKey("SEMIANNUALLY_DISCOUNT")) {
                        try {
                            discountPercentage = Double.parseDouble(server.getAttributes().get("SEMIANNUALLY_DISCOUNT").toString());
                        } catch (NumberFormatException e) {
                            // Use default of 0% if attribute value is invalid
                        }
                    }
                    break;
                case "YEARLY":
                    if (server.getAttributes().containsKey("YEARLY")) {
                        try {
                            discountPercentage = Double.parseDouble(server.getAttributes().get("YEARLY").toString());
                        } catch (NumberFormatException e) {
                            // Use default of 0% if attribute value is invalid
                        }
                    }
                    break;
                default:
                    // No discount for other cycles
                    break;
            }
        }
        
        return discountPercentage;
    }

    private String createPaymentProviderCustomer(User user, List<Long> deviceIds) {
        try {
            // Prepare request data
            Map<String, Object> requestData = new HashMap<>();
            requestData.put("name", user.getName());
            requestData.put("email", user.getEmail());
            requestData.put("externalReference", user.getId());
            
            // Add device IDs as observations
            if (!deviceIds.isEmpty()) {
                requestData.put("observations", "Device IDs: " + deviceIds.toString());
            }
            
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

    private String createPaymentProviderSubscription(User user, String customerId, String cycle, List<Device> devices, double discountPercentage) {
        try {
            // Calculate tomorrow's date
            LocalDate tomorrow = LocalDate.now().plusDays(1);
            String nextDueDate = tomorrow.format(DateTimeFormatter.ISO_DATE);
            
            // Calculate billing value from provided devices
            double billingValue = calculateTotalBillingValue(devices);
            
            // Adjust billing value based on cycle
            switch (cycle) {
                case "WEEKLY":
                    billingValue = billingValue / 4; // Approximately 1/4 of a month
                    break;
                case "BIWEEKLY":
                    billingValue = billingValue / 2; // Approximately 1/2 of a month
                    break;
                case "BIMONTHLY":
                    billingValue = billingValue * 2; // 2 months
                    break;
                case "QUARTERLY":
                    billingValue = billingValue * 3; // 3 months
                    break;
                case "SEMIANNUALLY":
                    billingValue = billingValue * 6; // 6 months
                    break;
                case "YEARLY":
                    billingValue = billingValue * 12; // 12 months
                    break;
                // MONTHLY: no adjustment needed (default monthly rate)
            }
            
            // Apply discount if applicable
            if (discountPercentage > 0) {
                billingValue = billingValue * (1 - discountPercentage / 100);
                // Round to one decimal place
                billingValue = Math.round(billingValue * 10) / 10.0;
            }
            
            // Prepare request data
            Map<String, Object> requestData = new HashMap<>();
            requestData.put("customer", customerId);
            requestData.put("billingType", "UNDEFINED");
            requestData.put("value", billingValue);
            requestData.put("cycle", cycle);
            requestData.put("nextDueDate", nextDueDate);
            requestData.put("description", config.getString(Keys.PAYMENT_DESCRIPTION));
            requestData.put("externalReference", user.getId());
            
            // Add discount if applicable
            if (discountPercentage > 0) {
                Map<String, Object> discount = new HashMap<>();
                discount.put("value", discountPercentage);
                discount.put("type", "PERCENTAGE");
                requestData.put("discount", discount);
            }
            
            Map<String, Object> callback = new HashMap<>();
            callback.put("successUrl", config.getString(Keys.PAYMENT_SUCCESS_URL));
            callback.put("autoRedirect", true);
            requestData.put("callback", callback);
            
            // Make API request to payment provider
            String apiEndpoint = config.getString(Keys.PAYMENT_API_ENDPOINT) + "/v3/subscriptions";
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
                    "Payment provider subscription error: Status=%d, Response=%s", 
                    status, 
                    errorBody.isEmpty() ? "[empty response]" : errorBody));
            }
            
            // Get subscription ID from response
            Map<String, Object> responseData = response.readEntity(new GenericType<Map<String, Object>>() {});
            if (responseData == null || !responseData.containsKey("id")) {
                throw new RuntimeException("Invalid response from payment provider: missing subscription ID");
            }
            return responseData.get("id").toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create payment provider subscription: " + e.getMessage(), e);
        }
    }
    
    private double calculateTotalBillingValue(List<Device> devices) {
        double total = 0.0;
        
        // Sum up plan values from devices
        for (Device device : devices) {
            if (device.getAttributes() != null && device.getAttributes().containsKey("planValue")) {
                try {
                    Object value = device.getAttributes().get("planValue");
                    if (value instanceof Number) {
                        total += ((Number) value).doubleValue();
                    } else if (value instanceof String) {
                        total += Double.parseDouble((String) value);
                    }
                } catch (NumberFormatException e) {
                    // Skip invalid values
                }
            }
        }
        
        // If no devices have planValue, set a minimum value
        if (total <= 0) {
            total = 34.9;
        }
        
        // Format to one decimal place
        total = Math.round(total * 10) / 10.0;
        
        return total;
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

    @Path("subscription")
    @PermitAll
    @POST
    public Response handleWebhook(Map<String, Object> data, @HeaderParam("asaas-access-token") String accessToken) throws StorageException {
        try {
            // Validate access token
            String configuredToken = config.getString(Keys.ASAAS_ACCESS_TOKEN);
            if (configuredToken != null && !configuredToken.isEmpty() && !configuredToken.equals(accessToken)) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("Invalid access token")
                        .build();
            }
            
            // Validate payload
            if (data == null) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Empty payload").build();
            }

            // Check if event is related to a subscription
            if (!data.containsKey("subscription")) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Missing subscription data").build();
            }

            Object subscriptionObj = data.get("subscription");
            if (!(subscriptionObj instanceof Map)) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Invalid subscription format").build();
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> subscription = (Map<String, Object>) subscriptionObj;
            
            // Validate subscription object
            if (subscription == null || !subscription.containsKey("object") || 
                !subscription.get("object").equals("subscription")) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Invalid subscription data").build();
            }

            // Extract required fields
            if (!subscription.containsKey("id") || !subscription.containsKey("status")) {
                return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Missing subscription id or status").build();
            }

            String subscriptionId = subscription.get("id").toString();
            String status = subscription.get("status").toString();
            
            // Get user ID from externalReference if available
            Long userId = null;
            if (subscription.containsKey("externalReference") && subscription.get("externalReference") != null) {
                try {
                    userId = Long.parseLong(subscription.get("externalReference").toString());
                } catch (NumberFormatException e) {
                    // Invalid user ID format, will fall back to searching all devices
                }
            }

            // Find all devices with this subscription ID
            List<Device> devices = getDevicesBySubscriptionId(subscriptionId, userId);

            if (devices.isEmpty()) {
                return Response.status(Response.Status.OK)
                    .entity("No devices found for subscription: " + subscriptionId).build();
            }

            // Update device status based on subscription status
            boolean disable = status.equals("INACTIVE");
            updateDevicesStatus(devices, disable);

            return Response.status(Response.Status.OK)
                .entity("Processed " + devices.size() + " devices for subscription " + subscriptionId).build();
                
        } catch (ClassCastException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity("Invalid payload format: " + e.getMessage()).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity("Error processing webhook: " + e.getMessage()).build();
        }
    }

    private List<Device> getDevicesBySubscriptionId(String subscriptionId, Long userId) throws StorageException {
        List<Device> result = new LinkedList<>();
        
        // Get devices - either all or just for a specific user
        Collection<Device> devices;
        if (userId != null) {
            // Only query devices belonging to this user
            devices = storage.getObjects(Device.class, new Request(
                    new Columns.All(),
                    new Condition.Permission(User.class, userId, Device.class)));
        } else {
            // Fall back to querying all devices if no user ID provided
            devices = storage.getObjects(Device.class, new Request(new Columns.All()));
        }
        
        // Filter devices with matching subscription ID
        for (Device device : devices) {
            if (device.getAttributes() != null && 
                device.getAttributes().containsKey("subscriptionId") && 
                subscriptionId.equals(device.getAttributes().get("subscriptionId").toString())) {
                result.add(device);
            }
        }
        
        return result;
    }

    private void updateDevicesStatus(List<Device> devices, boolean disable) throws StorageException {
        for (Device device : devices) {
            device.setDisabled(disable);
            storage.updateObject(device, new Request(
                    new Columns.Include("disabled"),
                    new Condition.Equals("id", device.getId())));
        }
    }

}
