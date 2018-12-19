// © https://github.com/scherma
// contact http_error_418@unsafehex.com

var moment = require('moment');
var options = require('./options');
var Promise = require('bluebird');
var dbparams = {
	client: 'pg',
	connection: {
		user: options.conf.database.username,
		database: options.conf.database.name,
		password: options.conf.database.password,
		host:"localhost"}
	};
var pg = require('knex')(dbparams);

function isServiceRegistered(guid) {
	return pg('victims').select('*').where({guid:guid})
	.then(function(result)
	{
		return (result.length > 0);
	});
}

function vmCanRegister(vmname) {
	return pg('victims').select('*').where({libvirtname: vmname}).andWhereNot({status: 'production'})
	.then(function(result)
	{
		return (result.length > 0);
	});
}

function registerVictimService(regparams) {
	var officetype = 0;
	switch(regparams.officeversionnum) {
		case "12.0":
			officeType = 1;
			break;
		case "14.0":
			officeType = 2;
			break;
		case "15.0":
			officeType = 3;
			break;
		case "16.0":
			officeType = 4;
			break;
		default:
			break;
	}
	
	console.log(regparams);
	
	return pg('victims').update({
		guid: regparams.guid,
		ip: regparams.ip,
		os: regparams.osname,
		ms_office_type: officetype,
		ms_office_string: regparams.officeversionstring,
		username: regparams.username,
		password: regparams.password,
		display_x: regparams.displaywidth,
		display_y: regparams.displayheight,
		malware_pos_x: regparams.malwarex,
		malware_pos_y: regparams.malwarey
		}).where({libvirtname: regparams.vmname});
}

function findCaseForVM(guid, state) {
	return pg.select('cases.*', 'victims.username')
	.from('cases')
	.innerJoin('workerstate', 'cases.uuid', 'workerstate.job_uuid')
	.innerJoin('victims', 'workerstate.uuid', 'victims.uuid')
	.where({'victims.guid': guid}).andWhere({'cases.status': state}).andWhereNot('workerstate.position', 'idle');
}

function sysmonInsert(rows) {
	return pg('sysmon_evts').insert(rows);
}

function markCaseObtained(uuid) {
	return pg('cases')
	.where({"uuid": uuid})
	.update({"status": "obtained"});
}

function markCaseAgentDone(guid) {
	return pg.select('cases.*')
	.from('cases')
	.innerJoin('workerstate', 'cases.uuid', 'workerstate.job_uuid')
	.innerJoin('victims', 'workerstate.uuid', 'victims.uuid')
	.where({'victims.guid': guid})
	.then((rows) => {
		pg('cases')
		.where({uuid: rows[0].uuid})
		.update({status: 'agent done'})
		.then(() => {
			console.log('updated ' + rows[0].uuid + ' to status "agent done"');
		});
	});
}

module.exports = {
	isServiceRegistered: isServiceRegistered,
	vmCanRegister: vmCanRegister,
	registerVictimService: registerVictimService,
	findCaseForVM: findCaseForVM,
	markCaseObtained: markCaseObtained,
	sysmonInsert: sysmonInsert,
	markCaseAgentDone: markCaseAgentDone
};