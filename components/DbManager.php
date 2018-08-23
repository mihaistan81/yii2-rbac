<?php

/*
 * This file is part of the Dektrium project.
 *
 * (c) Dektrium project <http://github.com/dektrium>
 *
 * For the full copyright and license information, please view the LICENSE.md
 * file that was distributed with this source code.
 */

namespace bpopescu\rbac\components;

use yii\rbac\Assignment;
use bpopescu\rbac\Role;
use bpopescu\rbac\Permission;
use yii\db\Expression;
use yii\db\Query;
use yii\rbac\DbManager as BaseDbManager;
use yii\rbac\Item;

/**
 * This Auth manager changes visibility and signature of some methods from \yii\rbac\DbManager.
 *
 * @author Dmitry Erofeev <dmeroff@gmail.com>
 */
class DbManager extends BaseDbManager implements ManagerInterface
{

    public $itemChildTable = '{{%auth_item_hierarchy}}';

    /**
     * @param  int|null $type         If null will return all auth items.
     * @param  array    $excludeItems Items that should be excluded from result array.
     * @return array
     */
    public function getItems($type = null, $excludeItems = [])
    {
        $query = (new Query())
            ->from($this->itemTable);

        if ($type !== null) {
            $query->where(['type' => $type]);
        } else {
            $query->orderBy('type');
        }

        foreach ($excludeItems as $name) {
            $query->andWhere('name != :item', ['item' => $name]);
        }

        $items = [];

        foreach ($query->all($this->db) as $row) {
            $items[$row['id']] = $this->populateItem($row);
        }

        return $items;
    }

    /**
     * Returns both roles and permissions assigned to user.
     *
     * @param  integer $userId
     * @return array
     */
    public function getItemsByUser($userId)
    {
        if (empty($userId)) {
            return [];
        }

        $query = (new Query)->select('b.*')
            ->from(['a' => $this->assignmentTable, 'b' => $this->itemTable])
            ->where('{{a}}.[[auth_item_id]]={{b}}.[[name]]')
            ->andWhere(['a.user_id' => (string) $userId]);

        $roles = [];
        foreach ($query->all($this->db) as $row) {
            $roles[$row['name']] = $this->populateItem($row);
        }
        return $roles;
    }

    /**
     * @inheritdoc
     */
    public function checkAccess($userId, $permissionName, $params = [])
    {
        $assignments = $this->getAssignments($userId);
        if (!isset($params['user'])) {
            $params['user'] = $userId;
        }
        return $this->checkAccessRecursive($userId, $permissionName, $params, $assignments);
    }

    /**
     * Performs access check for the specified user.
     * This method is internally called by [[checkAccess()]].
     * @param string|integer $user the user ID. This should can be either an integer or a string representing
     * the unique identifier of a user. See [[\yii\web\User::id]].
     * @param int $itemId the id of the operation that need access check
     * @param array $params name-value pairs that would be passed to rules associated
     * with the tasks and roles assigned to the user. A param with name 'user' is added to this array,
     * which holds the value of `$userId`.
     * @param Assignment[] $assignments the assignments to the specified user
     * @return boolean whether the operations can be performed by the user.
     */
    protected function checkAccessRecursive($user, $itemId, $params, $assignments)
    {
        if (($item = $this->getItemByName($itemId)) === null) {
            return false;
        }

        \Yii::trace($item instanceof Role ? "Checking role: $itemId" : "Checking permission: $itemId", __METHOD__);

        if (!$this->executeRule($user, $item, $params)) {
            return false;
        }

        if (isset($this->defaultRoles[$itemId]) || isset($assignments[$itemId])) {
            return true;
        }

        $query = new Query;
        $parents = $query->select(['parent_auth_item_id'])
                         ->from($this->itemChildTable)
                         ->where(['child_auth_item_id' => $itemId])
                         ->column($this->db);

        foreach ($parents as $parent) {
            if ($this->checkAccessRecursive($user, $parent, $params, $assignments)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @inheritdoc
     */
    public function getItem($id)
    {
        $row = (new Query)->from($this->itemTable)
                          ->where(['id' => $id])
                          ->one($this->db);

        if ($row === false) {
            return null;
        }

        if (!isset($row['data']) || ($data = @unserialize($row['data'])) === false) {
            $data = null;
        }

        return $this->populateItem($row);
    }

    /**
     * @inheritdoc
     */
    public function getItemByName($name)
    {
        $row = (new Query)->from($this->itemTable)
                          ->where(['name' => $name])
                          ->one($this->db);

        if ($row === false) {
            return null;
        }

        if (!isset($row['data']) || ($data = @unserialize($row['data'])) === false) {
            $data = null;
        }

        return $this->populateItem($row);
    }

    /**
     * Returns a value indicating whether the database supports cascading update and delete.
     * The default implementation will return false for SQLite database and true for all other databases.
     * @return boolean whether the database supports cascading update and delete.
     */
    protected function supportsCascadeUpdate()
    {
        return strncmp($this->db->getDriverName(), 'sqlite', 6) !== 0;
    }

    /**
     * @inheritdoc
     */
    protected function addItem($item)
    {
        $time = time();
        if ($item->createdAt === null) {
            $item->createdAt = $time;
        }
        if ($item->updatedAt === null) {
            $item->updatedAt = $time;
        }
        $this->db->createCommand()
                 ->insert($this->itemTable, [
                     'name' => $item->name,
                     'type' => $item->type,
                     'description' => $item->description,
                     'auth_rule_id' => $item->ruleName,
                     'data' => $item->data === null ? null : serialize($item->data),
                     'created_at' => $item->createdAt,
                     'updated_at' => $item->updatedAt,
                 ])->execute();

        return true;
    }

    /**
     * @inheritdoc
     */
    protected function removeItem($item)
    {
        if (!$this->supportsCascadeUpdate()) {
            $this->db->createCommand()
                     ->delete($this->itemChildTable, ['or', 'parent=:name', 'child=:name'], [':name' => $item->name])
                     ->execute();
            $this->db->createCommand()
                     ->delete($this->assignmentTable, ['auth_item_id' => $item->name])
                     ->execute();
        }

        $this->db->createCommand()
                 ->delete($this->itemTable, ['name' => $item->name])
                 ->execute();

        return true;
    }

    /**
     * @inheritdoc
     */
    protected function updateItem($id, $item)
    {
        if (!$this->supportsCascadeUpdate() && $item->id !== $id) {
            $this->db->createCommand()
                     ->update($this->itemChildTable, ['parent_auth_item_id' => $item->id], ['parent_auth_item_id' => $id])
                     ->execute();
            $this->db->createCommand()
                     ->update($this->itemChildTable, ['child_auth_item_id' => $item->id], ['child_auth_item_id' => $id])
                     ->execute();
            $this->db->createCommand()
                     ->update($this->assignmentTable, ['auth_item_id' => $item->id], ['auth_item_id' => $id])
                     ->execute();
        }

        $item->updatedAt = time();

        $this->db->createCommand()
                 ->update($this->itemTable, [
                     'name' => $item->name,
                     'description' => $item->description,
                     'auth_rule_id' => $item->ruleId,
                     'data' => $item->data === null ? null : serialize($item->data),
                     'updated_at' => $item->updatedAt,
                 ], [
                     'id' => $id,
                 ])->execute();

        return true;
    }

    /**
     * @inheritdoc
     */
    protected function addRule($rule)
    {
        $time = time();
        if ($rule->createdAt === null) {
            $rule->createdAt = $time;
        }
        if ($rule->updatedAt === null) {
            $rule->updatedAt = $time;
        }
        $this->db->createCommand()
                 ->insert($this->ruleTable, [
                     'name' => $rule->name,
                     'data' => serialize($rule),
                     'created_at' => $rule->createdAt,
                     'updated_at' => $rule->updatedAt,
                 ])->execute();

        return true;
    }

    /**
     * @inheritdoc
     */
    protected function updateRule($name, $rule)
    {
        if (!$this->supportsCascadeUpdate() && $rule->name !== $name) {
            $this->db->createCommand()
                     ->update($this->itemTable, ['rule_name' => $rule->name], ['rule_name' => $name])
                     ->execute();
        }

        $rule->updatedAt = time();

        $this->db->createCommand()
                 ->update($this->ruleTable, [
                     'name' => $rule->name,
                     'data' => serialize($rule),
                     'updated_at' => $rule->updatedAt,
                 ], [
                     'name' => $name,
                 ])->execute();

        return true;
    }

    /**
     * @inheritdoc
     */
    protected function removeRule($rule)
    {
        if (!$this->supportsCascadeUpdate()) {
            $this->db->createCommand()
                     ->delete($this->itemTable, ['rule_name' => $rule->name])
                     ->execute();
        }

        $this->db->createCommand()
                 ->delete($this->ruleTable, ['name' => $rule->name])
                 ->execute();

        return true;
    }

    /**
     * Populates an auth item with the data fetched from database
     * @param array $row the data from the auth item table
     * @return Item the populated auth item instance (either Role or Permission)
     */
    protected function populateItem($row)
    {
        $class = $row['type'] == Item::TYPE_PERMISSION ? Permission::className() : Role::className();

        if (!isset($row['data']) || ($data = @unserialize($row['data'])) === false) {
            $data = null;
        }

        return new $class([
            'id' => $row['id'],
            'name' => $row['name'],
            'type' => $row['type'],
            'description' => $row['description'],
            'ruleId' => $row['auth_rule_id'],
            'data' => $data,
            'createdAt' => $row['created_at'],
            'updatedAt' => $row['updated_at'],
        ]);
    }

    /**
     * @inheritdoc
     */
    public function getRolesByUser($userId)
    {
        $query = (new Query)->select('b.*')
                            ->from(['a' => $this->assignmentTable, 'b' => $this->itemTable])
                            ->where('a.auth_item_id=b.name')
                            ->andWhere(['a.user_id' => $userId]);

        $roles = [];
        foreach ($query->all($this->db) as $row) {
            $roles[$row['name']] = $this->populateItem($row);
        }
        return $roles;
    }

    /**
     * @inheritdoc
     */
    public function getPermissionsByRole($roleName)
    {
        $childrenList = $this->getChildrenList();
        $result = [];
        $this->getChildrenRecursive($roleName, $childrenList, $result);
        if (empty($result)) {
            return [];
        }
        $query = (new Query)->from($this->itemTable)->where([
            'type' => Item::TYPE_PERMISSION,
            'name' => array_keys($result),
        ]);
        $permissions = [];
        foreach ($query->all($this->db) as $row) {
            $permissions[$row['name']] = $this->populateItem($row);
        }
        return $permissions;
    }

    /**
     * @inheritdoc
     */
    public function getPermissionsByUser($userId)
    {
        $query = (new Query)->select('auth_item_id')
                            ->from($this->assignmentTable)
                            ->where(['user_id' => $userId]);

        $childrenList = $this->getChildrenList();
        $result = [];
        foreach ($query->column($this->db) as $roleName) {
            $this->getChildrenRecursive($roleName, $childrenList, $result);
        }

        if (empty($result)) {
            return [];
        }

        $query = (new Query)->from($this->itemTable)->where([
            'type' => Item::TYPE_PERMISSION,
            'name' => array_keys($result),
        ]);
        $permissions = [];
        foreach ($query->all($this->db) as $row) {
            $permissions[$row['name']] = $this->populateItem($row);
        }
        return $permissions;
    }

    /**
     * Returns the children for every parent.
     * @return array the children list. Each array key is a parent item name,
     * and the corresponding array value is a list of child item names.
     */
    protected function getChildrenList()
    {
        $query = (new Query)->from($this->itemChildTable);
        $parents = [];
        foreach ($query->all($this->db) as $row) {
            $parents[$row['parent_auth_item_id']][] = $row['child_auth_item_id'];
        }
        return $parents;
    }

    /**
     * Recursively finds all children and grand children of the specified item.
     * @param string $name the name of the item whose children are to be looked for.
     * @param array $childrenList the child list built via [[getChildrenList()]]
     * @param array $result the children and grand children (in array keys)
     */
    protected function getChildrenRecursive($name, $childrenList, &$result)
    {
        if (isset($childrenList[$name])) {
            foreach ($childrenList[$name] as $child) {
                $result[$child] = true;
                $this->getChildrenRecursive($child, $childrenList, $result);
            }
        }
    }

    /**
     * @inheritdoc
     */
    public function getRule($name)
    {
        $row = (new Query)->select(['data'])
                          ->from($this->ruleTable)
                          ->where(['name' => $name])
                          ->one($this->db);
        return $row === false ? null : unserialize($row['data']);
    }

    /**
     * @inheritdoc
     */
    public function getRules()
    {
        $query = (new Query)->from($this->ruleTable);

        $rules = [];
        foreach ($query->all($this->db) as $row) {
            $rules[$row['name']] = unserialize($row['data']);
        }

        return $rules;
    }

    /**
     * @inheritdoc
     */
    public function getAssignment($roleName, $userId)
    {
        $row = (new Query)->from($this->assignmentTable)
                          ->where(['user_id' => $userId, 'auth_item_id' => $roleName])
                          ->one($this->db);

        if ($row === false) {
            return null;
        }

        if (!isset($row['data']) || ($data = @unserialize($row['data'])) === false) {
            $data = null;
        }

        return new \yii\rbac\Assignment([
            'userId' => $row['user_id'],
            'roleName' => $row['auth_item_id'],
            'createdAt' => $row['created_at'],
        ]);
    }

    /**
     * @inheritdoc
     */
    public function getAssignments($userId)
    {
        $query = (new Query)
            ->select(['a.*', 'b.name'])
            ->from(['a' => $this->assignmentTable, 'b' => $this->itemTable])
            ->where('{{a}}.[[auth_item_id]]={{b}}.[[id]]')
            ->andWhere(['a.user_id' => $userId]);

        $assignments = [];
        foreach ($query->all($this->db) as $row) {
            if (!isset($row['data']) || ($data = @unserialize($row['data'])) === false) {
                $data = null;
            }
            $assignments[$row['name']] = new \yii\rbac\Assignment([
                'userId' => $row['user_id'],
                'roleName' => $row['name'],
                'createdAt' => $row['created_at'],
            ]);
        }

        return $assignments;
    }

    /**
     * @inheritdoc
     */
    public function addChild($parent, $child)
    {
        if ($parent->id === $child->id) {
            throw new InvalidParamException("Cannot add '{$parent->name}' as a child of itself.");
        }

        if ($parent instanceof Permission && $child instanceof Role) {
            throw new InvalidParamException("Cannot add a role as a child of a permission.");
        }

        if ($this->detectLoop($parent, $child)) {
            throw new InvalidCallException("Cannot add '{$child->name}' as a child of '{$parent->name}'. A loop has been detected.");
        }

        $this->db->createCommand()
                 ->insert($this->itemChildTable, ['parent_auth_item_id' => $parent->id, 'child_auth_item_id' => $child->id])
                 ->execute();
        return true;
    }

    /**
     * @inheritdoc
     */
    public function removeChild($parent, $child)
    {
        return $this->db->createCommand()
                        ->delete($this->itemChildTable, ['parent_auth_item_id' => $parent->id, 'child_auth_item_id' => $child->id])
                        ->execute() > 0;
    }

    /**
     * {@inheritdoc}
     */
    public function removeChildren($parent)
    {
        $result = $this->db->createCommand()
                           ->delete($this->itemChildTable, ['parent_auth_item_id' => $parent->id])
                           ->execute() > 0;

        $this->invalidateCache();

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function getChildren($id)
    {
        $query = (new Query())
            ->select(['a.id','name', 'type', 'description', 'auth_rule_id', 'data', 'created_at', 'updated_at'])
            ->from(['a' => $this->itemTable, 'b' => $this->itemChildTable])
            ->where(['parent_auth_item_id' => $id, 'a.id' => new Expression('[[child_auth_item_id]]')]);

        $children = [];
        foreach ($query->all($this->db) as $row) {
            $children[$row['id']] = $this->populateItem($row);
        }

        return $children;
    }

    /**
     * Checks whether there is a loop in the authorization item hierarchy.
     * @param Item $parent the parent item
     * @param Item $child the child item to be added to the hierarchy
     * @return boolean whether a loop exists
     */
    protected function detectLoop($parent, $child)
    {
        if ($child->id === $parent->id) {
            return true;
        }
        foreach ($this->getChildren($child->id) as $grandchild) {
            if ($this->detectLoop($parent, $grandchild)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @inheritdoc
     */
    public function assign($role, $userId, $rule = null, $data = null)
    {
        $assignment = new Assignment([
            'userId' => $userId,
            'roleName' => $role->name,
            'createdAt' => time(),
        ]);

        $this->db->createCommand()
                 ->insert($this->assignmentTable, [
                     'user_id' => $assignment->userId,
                     'auth_item_id' => $assignment->roleName,
                     'created_at' => $assignment->createdAt,
                 ])->execute();

        return $assignment;
    }

    /**
     * @inheritdoc
     */
    public function revoke($role, $userId)
    {
        return $this->db->createCommand()
                        ->delete($this->assignmentTable, ['user_id' => $userId, 'auth_item_id' => $role->name])
                        ->execute() > 0;
    }

    /**
     * @inheritdoc
     */
    public function revokeAll($userId)
    {
        return $this->db->createCommand()
                        ->delete($this->assignmentTable, ['user_id' => $userId])
                        ->execute() > 0;
    }

    /**
     * Removes all authorization data.
     */
    public function clearAll()
    {
        $this->clearAssignments();
        $this->db->createCommand()->delete($this->itemChildTable)->execute();
        $this->db->createCommand()->delete($this->itemTable)->execute();
        $this->db->createCommand()->delete($this->ruleTable)->execute();
    }

    /**
     * Removes all authorization assignments.
     */
    public function clearAssignments()
    {
        $this->db->createCommand()->delete($this->assignmentTable)->execute();
    }

    public function getRole($id)
    {
        $item = $this->getItem($id);
        return $item instanceof Item && $item->type == Item::TYPE_ROLE ? $item : null;
    }

    /**
     * {@inheritdoc}
     */
    public function getPermission($id)
    {
        $item = $this->getItem($id);
        return $item instanceof Item && $item->type == Item::TYPE_PERMISSION ? $item : null;
    }

    /**
     * {@inheritdoc}
     */
    public function createRole($name)
    {
        $role = new Role();
        $role->name = $name;
        return $role;
    }

    /**
     * {@inheritdoc}
     */
    public function createPermission($name)
    {
        $permission = new Permission();
        $permission->name = $name;
        return $permission;
    }
}