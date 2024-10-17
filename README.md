# Schedule Easy

Welcome to **Schedule Easy**, a simple and efficient scheduling tool designed to help you manage your time effectively.

## Features

- **User-friendly Interface**: Easy to navigate and use.
- **Customizable Schedules**: Create and manage your own schedules.
- **Reminders**: Set reminders for important tasks and events.
- **Cross-Platform**: Available on multiple platforms.


## Installation

To install Schedule Easy, follow these steps:

1. Clone the repository:
    ```sh
    git clone https://github.com/vaibhav191/schedule-easy.git
    ```
2. Navigate to the project directory:
    ```sh
    cd schedule-easy
    ```
3. Launch:
    ```sh
    docker compose up -d --build
    ```

## DEPENDENCIES
docker & docker compose

## Environment Variables

Create a `.env` file in the root directory and add the following environment variables:

### KMS
```plaintext
AUTH_KMS_ACCOUNT_ID= (AWS Account detail with user access to KMS)
AUTH_KMS_ACCESS_KEY= ""
AUTH_KMS_SECRET_KEY= ""
AUTH_KMS_REGION= ""
AUTH_APP_CREDENTIALS_KEYID= (AWS KMS key id)
MSG_APP_MAC_KEYID= (AWS KMS key id)
NOTIFICATION_APP_MAC_KEYID= (AWS KMS key id)
```

### Auth Credentials (Insecure for Development)
```plaintext
OAUTHLIB_INSECURE_TRANSPORT= (1 for development since oauth can't run on http)
```

### Auth Service
```plaintext
AUTH_ADDRESS=
AUTH_PORT=
SESSION_SECRET=
```

### Mongo Service
```plaintext
MONGO_ADDRESS=
MONGO_PORT=
```

### RabbitMQ Service
```plaintext
RABBITMQ_AMQP_PORT=
RABBITMQ_MGMT_PORT=
RABBITMQ_USERNAME=
RABBITMQ_PASSWORD=
```

### Redis Service
```plaintext
REDIS_HOST=
REDIS_PORT=
```

### Crypto Service
```plaintext
CRYPTO_PORT=
ENCRYPTED_GOOGLE_APP_CRED= (encrypted with AUTH_APP_CREDENTIALS_KEYID)
```

### Gateway Service
```plaintext
GATEWAY_PORT=
```

### Message Service
```plaintext
MSG_PORT=
```

### Notification Service
```plaintext
NOTIFICATION_EMAIL_ID= (username)
NOTIFICATION_EMAIL_PASSWORD= (password)
```
### NGINX
```plaintext
NGINX_PORT=80
SITE_DOMAIN=https://localhost
```

## Contributing

We welcome contributions! Please read our [contributing guidelines](CONTRIBUTING.md) for more details.


## Contact

For any questions or feedback, please contact us at vaibhavshrivastava44@gmail.com 
