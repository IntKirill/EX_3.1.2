package ru.kata.spring.boot_security.demo.demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.kata.spring.boot_security.demo.demo.model.Role;
import ru.kata.spring.boot_security.demo.demo.model.User;
import ru.kata.spring.boot_security.demo.demo.repositories.UserRepository;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

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

    @Override
    public User getUserById(Long id) {
        return userRepository.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
    }

    @Override
    public User findByUsername(String name) {
        return userRepository.findByUsername(name).orElse(null);
    }

    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public void saveUser(User user) {

        // Присваиваем новые роли
        Role userRole = roleService.findByName("ROLE_USER")
                .orElseThrow(() -> new IllegalStateException("Role 'ROLE_USER' not found"));
        user.getRoles().add(userRole);

        // Проверяем, был ли изменён пароль
        if (user.getPassword() != null && !user.getPassword().isEmpty()) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));

            // Сохраняем пользователя
            userRepository.save(user);
        }
    }

    @Override
    public void deleteUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalStateException("User with id " + id + " not found"));

        if (user.getRoles().stream().anyMatch(role -> role.getName().equals("ROLE_ADMIN"))) {
            throw new IllegalStateException("Нельзя удалить администратора!");
        }

        userRepository.delete(user);
    }



    @Override
    public void updateUser(Long id, User user, List<Long> roleIds) {
        // Получаем пользователя из базы данных
        User existingUser = userRepository.findById(id)
                .orElseThrow(() -> new IllegalStateException("User with id " + id + " not found"));

        // Проверяем, является ли пользователь администратором
        boolean isAdmin = existingUser.getRoles().stream()
                .anyMatch(role -> role.getName().equals("ROLE_ADMIN"));

        if (isAdmin) {
            throw new IllegalStateException("Нельзя изменить администратора!");
        }

        // Обновляем основные поля пользователя
        existingUser.setUsername(user.getUsername());
        existingUser.setCountry(user.getCountry());
        existingUser.setCar(user.getCar());

        // Проверяем, если пароль был передан и он не пустой
        if (user.getPassword() != null && !user.getPassword().trim().isEmpty()) {
            // Если пароль не пустой и отличается от старого пароля, хешируем новый пароль
            if (!user.getPassword().equals(existingUser.getPassword())) {
                existingUser.setPassword(passwordEncoder.encode(user.getPassword()));
            }
        }




        // Получаем список ролей по ID
        if (roleIds != null && !roleIds.isEmpty()) {
            // Получаем список ролей по ID
            List<Role> roles = roleService.findRolesByIds(roleIds);

            // Проверяем, что роли были найдены
            if (roles.isEmpty()) {
                throw new IllegalStateException("❌ Указанные роли не найдены!");
            }

            // Преобразуем список в Set и устанавливаем роли пользователю
            existingUser.setRoles(new HashSet<>(roles));
        } else {
            // Если роли не выбраны, оставляем текущие роли пользователя
            // В этом случае мы просто не меняем роли
        }

        // Сохраняем обновленного пользователя
        userRepository.save(existingUser);
    }
}
