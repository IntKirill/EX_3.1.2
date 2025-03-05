package ru.kata.spring.boot_security.demo.demo.service;

import ru.kata.spring.boot_security.demo.demo.model.User;

import java.util.List;

public interface UserService {

    User getUserById(Long id);

    User findByUsername(String name);

    List<User> getAllUsers();

    void saveUser(User user);

    void deleteUser(Long id);


    void updateUser(Long id, User user,List<Long> roleIds);
}
