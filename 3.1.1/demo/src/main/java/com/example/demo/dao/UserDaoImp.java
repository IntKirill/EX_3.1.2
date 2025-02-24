package com.example.demo.dao;

import com.example.demo.model.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Repository;



import java.util.List;


@Repository
public class UserDaoImp implements UserDao {


    @PersistenceContext
    public EntityManager entityManager;

    @Transactional
    @Override
    public void save (User user) {
        entityManager.persist(user);
        //добавление
    }
    @Transactional
@Override
public User findById(Long id) {
        return entityManager.find(User.class, id);
        //получение
    }

    @Transactional
    @Override
    public void removeUserById(long id) {
        User user = entityManager.find(User.class, id);
        entityManager.remove(user);
        //удаление по ид
    }

    @Transactional
    @Override
    public void updateUser(User user) {
        entityManager.merge(user);
        //изменение по ид
    }
    @Transactional
    @Override
    public List<User> findAll() {
        return entityManager.createQuery("FROM User", User.class).getResultList();
        //весь список
    }
}
