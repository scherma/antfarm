// © https://github.com/scherma
// contact http_error_418@unsafehex.com

var moment = require('moment');
var options = require('./options');
var Promise = require('bluebird');
var dbparams = {
	client: 'pg',
	connection: {
		user: options.conf.database.username,
		database: options.conf.site.name,
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

function vmExists(vmname) {
	return pg('victims').select('*').where({vmname: vmname})
	.then(function(result)
	{
		return (result.length > 0);
	});
}

function registerVictimService(guid,
							   vmname,
							   vmip,
							   osname,
							   officeVersionString,
							   officeVersionNum,
							   username,
							   password,
							   displayHeight,
							   displayWidth,
							   malwareX,
							   malwareY) {
	var officeType = 0;
	switch(officeVersionNum) {
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
	
	return pg('victims').update({
		guid: guid,
		ip: vmip,
		os: osname,
		ms_office_type: officeType,
		ms_office_name: officeVersionString,
		username: username,
		password: password,
		display_x: displayWidth,
		display_y: displayHeight,
		malware_pos_x: malwareX,
		malware_pos_y: malwareY
		}).where({vmname: vmname});
}

function findCaseForVM(guid) {
	return pg.select('cases.*', 'victims.username')
	.from('cases')
	.innerJoin('workerstate', 'cases.uuid', 'workerstate.job_uuid')
	.innerJoin('victims', 'workerstate.uuid', 'victims.uuid')
	.where({'victims.guid': guid}).andWhereNot('workerstate.position', 'idle');
}

function sysmonInsert(rows) {
	return pg('sysmon_evts').insert(rows);
}

function markCaseObtained(uuid) {
	return pg('cases')
	.where({"uuid": uuid})
	.update({"status": "obtained"});
}

module.exports = {
	isServiceRegistered: isServiceRegistered,
	vmExists: vmExists,
	registerVictimService: registerVictimService,
	findCaseForVM: findCaseForVM,
	markCaseObtained: markCaseObtained,
	sysmonInsert: sysmonInsert
};