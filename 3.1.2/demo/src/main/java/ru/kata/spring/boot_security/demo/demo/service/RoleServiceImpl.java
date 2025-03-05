package ru.kata.spring.boot_security.demo.demo.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import ru.kata.spring.boot_security.demo.demo.model.Role;
import ru.kata.spring.boot_security.demo.demo.repositories.RoleRepository;

import java.util.List;
import java.util.Optional;

@Service
public class RoleServiceImpl  implements RoleService {

    private RoleRepository roleRepository;

@Autowired
    public RoleServiceImpl(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    // Метод для поиска роли по имени
    @Override
    public Optional<Role> findByName(String roleName) {
        return roleRepository.findByName(roleName);
    }

    // Метод для сохранения роли
    @Override
    public Role save(Role role) {
        return roleRepository.save(role);
    }
@Override
    public List<Role> getAllRoles() {
        return roleRepository.findAll();
    }
@Override
    public List<Role> findRolesByIds(List<Long> roleIds) {
        return roleRepository.findAllById(roleIds);
    }
    public Optional<Role> findById(Long id) {
        return roleRepository.findById(id);
    }


}
