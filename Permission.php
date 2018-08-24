<?php
namespace bpopescu\rbac;

class Permission extends Item
{
    /**
     * @var int
     */
    public $id;

    /**
     * @var id of the rule associated with this item
     */
    public $ruleId;

    public $type = self::TYPE_PERMISSION;
}