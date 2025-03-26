/*
 * Copyright 2018 - 2024 Anton Tananaev (anton@traccar.org)
 * Copyright 2018 Andrey Kunitsyn (andrey@traccar.org)
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
package org.traccar.notificators;

import com.niamedtech.expo.exposerversdk.ExpoPushNotificationClient;
import com.niamedtech.expo.exposerversdk.request.PushNotification;
import com.niamedtech.expo.exposerversdk.response.Status;
import com.niamedtech.expo.exposerversdk.response.TicketResponse;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.model.Event;
import org.traccar.model.ObjectOperation;
import org.traccar.model.Position;
import org.traccar.model.User;
import org.traccar.notification.MessageException;
import org.traccar.notification.NotificationFormatter;
import org.traccar.notification.NotificationMessage;
import org.traccar.session.cache.CacheManager;
import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Singleton
public class NotificatorExpo extends Notificator {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificatorExpo.class);
    private final String accessToken;
    private final Storage storage;
    private final CacheManager cacheManager;


    @Inject
    public NotificatorExpo(
            Config config,
            NotificationFormatter notificationFormatter,
            Storage storage, CacheManager cacheManager
            ) throws IOException {
        super(notificationFormatter, "short");

        this.accessToken = config.getString(Keys.EXPO_ACCESS_TOKEN);
        this.storage = storage;
        this.cacheManager = cacheManager;
    }

    @Override
    public void send(User user, NotificationMessage message, Event event, Position position) throws MessageException {
        if (user.hasAttribute("notificationTokens")) {

            List<String> registrationTokens = new ArrayList<>(
                    Arrays.asList(user.getString("notificationTokens").split("[, ]")));
            try {
                CloseableHttpClient httpClient = HttpClients.createDefault();

                ExpoPushNotificationClient client = ExpoPushNotificationClient
                        .builder()
                        .setHttpClient(httpClient)
                        .setAccessToken(this.accessToken)
                        .build();

                PushNotification pushNotification = new PushNotification();
                pushNotification.setTo(registrationTokens);
                pushNotification.setTitle(message.getSubject());
                pushNotification.setBody(message.getBody());
                pushNotification.setSound("horn.wav");

                List<PushNotification> notifications = new ArrayList<>();
                notifications.add(pushNotification);

                List<TicketResponse.Ticket> responses = client.sendPushNotifications(notifications);

                List<String> failedTokens = new LinkedList<>();

                for (TicketResponse.Ticket ticket : responses) {
                    if (ticket.getStatus() == Status.ERROR) {
                        failedTokens.add(ticket.getDetails().getExpoPushToken());
                    }
                }

                if (!failedTokens.isEmpty()) {
                    registrationTokens.removeAll(failedTokens);
                    if (registrationTokens.isEmpty()) {
                        user.getAttributes().remove("notificationTokens");
                    } else {
                        user.set("notificationTokens", String.join(",", registrationTokens));
                    }
                    storage.updateObject(user, new Request(
                            new Columns.Include("attributes"),
                            new Condition.Equals("id", user.getId())));
                    cacheManager.invalidateObject(true, User.class, user.getId(), ObjectOperation.UPDATE);
                }

            } catch (Exception e) {
                LOGGER.warn("Notification error", e);
            }
        }
    }

}
