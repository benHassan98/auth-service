package com.odinbook.authserver.config;

import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitAdmin;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AMQPConfig {
    @Bean
    public RabbitAdmin rabbitAdmin(ConnectionFactory connectionFactory){

        return new RabbitAdmin(connectionFactory);
    }

}
