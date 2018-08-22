<?php
namespace bpopescu\rbac;

class Role extends Item
{
    /**
     * @var int
     */
    public $id;

    public $type = self::TYPE_ROLE;
}