package ru.kata.spring.boot_security.demo.demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.kata.spring.boot_security.demo.demo.model.Role;
import ru.kata.spring.boot_security.demo.demo.model.User;
import ru.kata.spring.boot_security.demo.demo.repositories.UserRepository;

import java.util.HashSet;
import java.util.List;

@Service
public class UserServiceImpl  implements UserService {


    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleService roleService;

    @Autowired
    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, RoleService roleService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleService = roleService;
    }
    @Transactional
    @Override
    public User getUserById(Long id) {
        return userRepository.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
    }
    @Transactional
    @Override
    public User findByUsername(String name) {
        return userRepository.findByUsername(name).orElse(null);
    }
    @Transactional
    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
    @Transactional
    @Override
    public void saveUser(User user) {
        Role userRole = roleService.findByName("ROLE_USER")
                .orElseThrow(() -> new IllegalStateException("Role 'ROLE_USER' not found"));
        user.getRoles().add(userRole);

        if (user.getPassword() != null && !user.getPassword().isEmpty()) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            userRepository.save(user);
        }
    }
    @Transactional
    @Override
    public void deleteUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalStateException("User with id " + id + " not found"));
        if (user.getRoles().stream().anyMatch(role -> role.getName().equals("ROLE_ADMIN"))) {
            throw new IllegalStateException("Нельзя удалить администратора!");
        }
        userRepository.delete(user);
    }

    @Transactional
    @Override
    public void updateUser(Long id, User user, List<Long> roleIds) {
        User existingUser = userRepository.findById(id)
                .orElseThrow(() -> new IllegalStateException("User with id " + id + " not found"));

        boolean isAdmin = existingUser.getRoles().stream()
                .anyMatch(role -> role.getName().equals("ROLE_ADMIN"))
                && existingUser.getUsername().equals("admin");

        if (isAdmin) {
            throw new IllegalStateException("Нельзя изменить администратора!");
        }
        existingUser.setUsername(user.getUsername());
        existingUser.setCountry(user.getCountry());
        existingUser.setCar(user.getCar());

        if (user.getPassword() != null && !user.getPassword().trim().isEmpty()) {
            if (!passwordEncoder.matches(user.getPassword(), existingUser.getPassword())) {
                existingUser.setPassword(passwordEncoder.encode(user.getPassword()));
            }
        }
        if (roleIds != null && !roleIds.isEmpty()) {
            List<Role> roles = roleService.findRolesByIds(roleIds);

            if (roles.isEmpty()) {
                throw new IllegalStateException("Указанные роли не найдены!");
            }
            existingUser.setRoles(new HashSet<>(roles));
        } else {
        }
        userRepository.save(existingUser);
    }
}
